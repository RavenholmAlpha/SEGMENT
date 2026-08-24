// Package client connects the tunnel client side: TLS dial (with a
// Chrome ClientHello fingerprint via uTLS), h2 fronting, ticket resume
// through the authentication POST with full-handshake fallback, credential persistence for instant
// reconnect, automatic tunnel supervision/reconnect, and the SOCKS5
// ingress wiring.
package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"segment/internal/auth"
	"segment/internal/h2x"
	"segment/internal/socks5"
	"segment/internal/tunnel"
)

// Options configures one client instance.
type Options struct {
	Server   string      // host:port
	SNI      string      // TLS SNI / :authority
	TLS      *tls.Config // stdlib config; used for RootCAs with either fingerprint
	H2Config h2x.Config  // zero -> DefaultConfig
	Insecure bool        // skip certificate verification (dev/testing)
	CredFile string      // optional credential cache file for persistence
	// Fingerprint selects the TLS ClientHello: "chrome" (default, uTLS
	// Chrome 133 spec) or "go" (stdlib crypto/tls).
	Fingerprint string
}

// Client is a connected tunnel client with its SOCKS5 ingress.
type Client struct {
	opts  Options
	authC *auth.Client

	mu           sync.Mutex
	cli          *tunnel.Client
	cred         *auth.ClientSession // latest resumable credential (single-use)
	closed       chan struct{}       // closed by Close()
	superviseRun sync.Once           // one supervision goroutine per client
}

// NewWithPSK builds a client struct with the shared pre-shared key.
func NewWithPSK(opts Options, psk []byte) (*Client, error) {
	if opts.Server == "" {
		return nil, errors.New("client: server required")
	}
	if opts.SNI == "" {
		host, _, err := net.SplitHostPort(opts.Server)
		if err != nil {
			return nil, errors.New("client: bad server address, use host:port")
		}
		opts.SNI = host
	}
	authC, err := auth.NewClient(psk)
	if err != nil {
		return nil, err
	}
	if opts.H2Config.Settings.MaxConcurrentStreams == 0 {
		opts.H2Config = h2x.DefaultConfig()
	}
	switch opts.Fingerprint {
	case "":
		opts.Fingerprint = "chrome" // default: uTLS Chrome ClientHello
	case "chrome", "go":
	default:
		return nil, errors.New("client: fingerprint must be \"chrome\" or \"go\"")
	}
	if opts.TLS == nil {
		opts.TLS = &tls.Config{}
	}
	opts.TLS = opts.TLS.Clone()
	opts.TLS.ServerName = opts.SNI
	opts.TLS.NextProtos = []string{"h2"}
	opts.TLS.InsecureSkipVerify = opts.Insecure
	opts.TLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	return &Client{opts: opts, authC: authC, closed: make(chan struct{})}, nil
}

// Connect dials the server, preferring ticket resume (using the cached
// credential, from memory or the credential file); on resume failure it
// falls back to the full handshake on a fresh connection, then starts
// the supervision goroutine that keeps the tunnel alive.
func (c *Client) Connect() error {
	c.mu.Lock()
	if c.cred == nil {
		c.cred = c.loadCredFile()
	}
	if c.cred != nil && !c.cred.Valid(time.Now()) {
		c.cred = nil
	}
	cred := c.cred
	c.mu.Unlock()

	if cred != nil {
		if err := c.connectOnce(); err == nil {
			// Resume consumed the single-use ticket: drop it so the
			// next connect does a full handshake (which issues a fresh
			// ticket). The credential file is stale as well.
			c.mu.Lock()
			c.cred = nil
			c.mu.Unlock()
			c.removeCredFile()
			c.superviseRun.Do(func() { go c.supervise() })
			return nil
		} else {
			log.Printf("ticket resume failed (%v); falling back to full handshake", err)
			c.mu.Lock()
			c.cred = nil
			c.cli = nil
			c.mu.Unlock()
		}
	}
	if err := c.connectOnce(); err != nil {
		return err
	}
	if err := c.establish(); err != nil {
		// Tear down the just-built tunnel: without supervision it would
		// stay resident and dead (unauthenticated) forever.
		c.mu.Lock()
		cli := c.cli
		c.cli = nil
		c.mu.Unlock()
		if cli != nil {
			_ = cli.Close()
		}
		return err
	}
	c.superviseRun.Do(func() { go c.supervise() })
	return nil
}

// errClosed is returned by connection establishment when the client has
// been closed mid-flight (the partially-built tunnel is torn down).
var errClosed = errors.New("client: closed")

// connectOnce performs the TCP+TLS+h2 dial; when a valid credential is
// cached, tunnel.Dial completes the ticket-authentication POST before it
// opens any media-marked stream.
// Every blocking step observes c.closed: a Close() during a reconnect
// cancels the dial and tears the half-built tunnel down instead of
// installing a ghost connection nobody supervises.
func (c *Client) connectOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := make(chan struct{})
	defer close(watch)
	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-watch:
		}
	}()

	var d net.Dialer
	tc, err := d.DialContext(ctx, "tcp", c.opts.Server)
	if err != nil {
		return err
	}
	tconn, err := c.tlsDial(ctx, tc)
	if err != nil {
		_ = tc.Close()
		return err
	}
	c.mu.Lock()
	cred := c.cred
	c.mu.Unlock()
	// Bound the remaining handshake (h2 preface exchange + WaitReady)
	// as one block; cleared once the tunnel is ready.
	_ = tconn.SetDeadline(time.Now().Add(15 * time.Second))
	cli, err := tunnel.Dial(tconn, c.opts.H2Config, c.authC, cred, c.opts.SNI)
	if err != nil {
		_ = tconn.Close()
		return err
	}
	if err := cli.WaitReady(10 * time.Second); err != nil {
		_ = cli.Close()
		return err
	}
	_ = tconn.SetDeadline(time.Time{})

	c.mu.Lock()
	if c.isClosedLocked() {
		c.mu.Unlock()
		_ = cli.Close()
		return errClosed
	}
	if old := c.cli; old != nil && old != cli {
		_ = old.Close()
	}
	c.cli = cli
	c.mu.Unlock()
	return nil
}

// isClosed reports whether Close has been called.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosedLocked()
}

// isClosedLocked must be called with c.mu held.
func (c *Client) isClosedLocked() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// establish completes the full-handshake authentication on the current
// connection and persists the fresh credential.
func (c *Client) establish() error {
	cli := c.current()
	if cli == nil {
		return errors.New("client: no tunnel")
	}
	if err := cli.Establish(); err != nil {
		return err
	}
	cs := cli.ClientSession()
	c.mu.Lock()
	c.cred = cs
	c.mu.Unlock()
	c.saveCredFile(cs)
	return nil
}

// tlsDial wraps the TCP connection in TLS with the configured
// ClientHello fingerprint. The handshake is bounded; it also ends early
// when the client is closed mid-flight (the connectOnce watcher cancels
// ctx, which trips the deadline).
func (c *Client) tlsDial(ctx context.Context, tc net.Conn) (net.Conn, error) {
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second)) // bounded handshake
	if c.opts.Fingerprint == "go" {
		tlsConn := tls.Client(tc, c.opts.TLS)
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		_ = tc.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	// uTLS Chrome fingerprint: header shape matches a real Chrome 133
	// ClientHello (design doc §3.3).
	ucfg := &utls.Config{
		ServerName:         c.opts.SNI,
		InsecureSkipVerify: c.opts.Insecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if c.opts.TLS != nil && c.opts.TLS.RootCAs != nil {
		ucfg.RootCAs = c.opts.TLS.RootCAs
	}
	uconn := utls.UClient(tc, ucfg, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return uconn, nil
}

// supervise watches the tunnel connection and re-establishes it (with
// ticket resume when a fresh credential exists, else a full handshake)
// after any loss, with bounded, jittered backoff.
func (c *Client) supervise() {
	for {
		cli := c.current()
		if cli == nil {
			// A dial path may have cleared the tunnel (its connection
			// died); heal it instead of silently ending supervision.
			if c.isClosed() {
				return
			}
			if err := c.reconnect(); err != nil {
				select {
				case <-time.After(jitter(time.Second)):
				case <-c.closed:
					return
				}
			}
			continue
		}
		select {
		case <-c.closed:
			return
		case <-cli.Done():
		}
		log.Printf("tunnel connection lost; reconnecting")
		// Backoff with exponential growth, a hard cap and per-attempt
		// jitter: fixed-interval reconnects are both a statistical
		// fingerprint under censorship and a self-inflicted burst.
		backoff := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
		const maxBackoff = 30 * time.Second
		attempt := 0
		for {
			if err := c.reconnect(); err == nil {
				break
			} else if attempt < 3 {
				log.Printf("reconnect attempt failed: %v", err)
			}
			d := maxBackoff
			if attempt < len(backoff) {
				d = backoff[attempt]
			}
			attempt++
			select {
			case <-time.After(jitter(d)):
			case <-c.closed:
				return
			}
		}
		log.Printf("tunnel reconnected")
	}
}

// reconnect re-establishes the tunnel after a failure: ticket resume
// when a valid credential is cached, falling back to a full handshake
// (design-mandated: the server rotates its ticket key on restart, which
// invalidates outstanding tickets); a successful resume consumes the
// single-use ticket, so the next reconnect runs a full handshake for a
// fresh one.
func (c *Client) reconnect() error {
	c.mu.Lock()
	cred := c.cred
	c.cli = nil
	c.mu.Unlock()

	if cred != nil {
		if err := c.connectOnce(); err == nil {
			// Ticket resume confirmed; the ticket is now consumed.
			c.mu.Lock()
			c.cred = nil
			c.mu.Unlock()
			c.removeCredFile()
			return nil
		}
		// Resume failed (stale ticket after a server restart): discard
		// the ticket and run a full handshake on a fresh connection.
		c.mu.Lock()
		c.cred = nil
		c.mu.Unlock()
		c.removeCredFile()
	}
	if err := c.connectOnce(); err != nil {
		return err
	}
	return c.establish()
}

// jitter returns d randomized to ±30%, breaking fixed reconnect
// rhythms.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	frac := int64(d) / 3
	off := rand.Int64N(2*frac+1) - frac
	return d + time.Duration(off)
}

// current returns the live tunnel client (nil while reconnecting).
func (c *Client) current() *tunnel.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cli
}

// dialTCP handles a SOCKS5 CONNECT, waiting briefly for a reconnect in
// progress and retrying a stale tunnel once. Only a connection-level
// failure clears the tunnel (supervision heals it); a stream-level
// error (target refused, stream reset by the peer) is returned as-is so
// a healthy tunnel is never discarded on a per-target failure.
func (c *Client) dialTCP(dst string, port uint16) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cli := c.current()
		if cli == nil {
			if !c.waitForTunnel(5 * time.Second) {
				return nil, errors.New("client: tunnel unavailable")
			}
			continue
		}
		conn, err := cli.OpenTCP(dst, port)
		if err == nil {
			return conn, nil
		}
		if attempt == 1 {
			return nil, err
		}
		if !c.connDead(cli) {
			return nil, err // stream-level failure; tunnel is fine
		}
		// Tunnel connection died; let supervision heal it and retry.
		c.mu.Lock()
		if c.cli == cli {
			c.cli = nil
		}
		c.mu.Unlock()
		if !c.waitForTunnel(5 * time.Second) {
			return nil, err
		}
	}
	return nil, errors.New("client: tunnel unavailable")
}

// connDead reports whether the tunnel's h2 connection has failed.
func (c *Client) connDead(cli *tunnel.Client) bool {
	select {
	case <-cli.Done():
		return true
	default:
		return false
	}
}

// dialUDP handles a SOCKS5 UDP ASSOCIATE flow.
func (c *Client) dialUDP(dst string, port uint16) (socks5.UDPFlow, error) {
	for attempt := 0; attempt < 2; attempt++ {
		cli := c.current()
		if cli == nil {
			if !c.waitForTunnel(5 * time.Second) {
				return nil, errors.New("client: tunnel unavailable")
			}
			continue
		}
		flow, err := cli.OpenUDP(dst, port)
		if err == nil {
			return flow, nil
		}
		if attempt == 1 {
			return nil, err
		}
		if !c.connDead(cli) {
			return nil, err // stream-level failure; tunnel is fine
		}
		c.mu.Lock()
		if c.cli == cli {
			c.cli = nil
		}
		c.mu.Unlock()
		if !c.waitForTunnel(5 * time.Second) {
			return nil, err
		}
	}
	return nil, errors.New("client: tunnel unavailable")
}

// waitForTunnel polls until a tunnel is available or the timeout elapses.
func (c *Client) waitForTunnel(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.current() != nil {
			return true
		}
		select {
		case <-c.closed:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	return false
}

// Credential returns the cached resumable credential (updated after a
// full handshake; nil after a resume, since tickets are single-use).
func (c *Client) Credential() *auth.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cred
}

// OpenTCPRaw opens a raw tunneled TCP connection to a target (bypasses
// SOCKS5; used by integrations and benchmarks).
func (c *Client) OpenTCPRaw(addr string, port uint16) (net.Conn, error) {
	cli := c.current()
	if cli == nil {
		return nil, errors.New("client: tunnel unavailable")
	}
	return cli.OpenTCP(addr, port)
}

// ServerAddr returns the configured server address.
func (c *Client) ServerAddr() string { return c.opts.Server }

// SOCKSListener binds the SOCKS5 ingress on addr and serves it in the
// background. The returned listener can be closed to stop serving.
func (c *Client) SOCKSListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h := &socks5.Handler{
		DialTCP: c.dialTCP,
		DialUDP: c.dialUDP,
	}
	go h.Serve(ln)
	return ln, nil
}

// ServeSOCKS starts the SOCKS5 ingress on addr (e.g. 127.0.0.1:1080)
// and blocks until the process exits.
func (c *Client) ServeSOCKS(addr string) error {
	_, err := c.SOCKSListener(addr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 listening on %s (tunnel %s)", addr, c.opts.Server)
	select {}
}

// Close tears the tunnel down and stops supervision.
func (c *Client) Close() error {
	c.mu.Lock()
	once := c.closed
	select {
	case <-once:
	default:
		close(once)
	}
	cli := c.cli
	c.cli = nil
	c.mu.Unlock()
	if cli != nil {
		return cli.Close()
	}
	return nil
}

// ---- credential persistence -------------------------------------------------

// credCache is the on-disk form of a resumable credential.
type credCache struct {
	Ticket  string `json:"ticket"`  // base64
	Key     string `json:"key"`     // base64
	Expires int64  `json:"expires"` // unix seconds
}

// loadCredFile reads and validates the credential cache file.
func (c *Client) loadCredFile() *auth.ClientSession {
	if c.opts.CredFile == "" {
		return nil
	}
	b, err := os.ReadFile(c.opts.CredFile)
	if err != nil {
		return nil
	}
	var cc credCache
	if err := json.Unmarshal(b, &cc); err != nil {
		return nil
	}
	if cc.Ticket == "" || cc.Key == "" {
		return nil
	}
	cs := &auth.ClientSession{Expires: time.Unix(cc.Expires, 0)}
	key, err := base64.StdEncoding.DecodeString(cc.Key)
	if err != nil || len(key) != len(cs.Key) {
		return nil
	}
	copy(cs.Key[:], key)
	ticket, err := base64.StdEncoding.DecodeString(cc.Ticket)
	if err != nil || len(ticket) == 0 {
		return nil
	}
	cs.Ticket = ticket
	if !cs.Valid(time.Now()) {
		return nil
	}
	return cs
}

// saveCredFile writes the credential cache file (0600, best-effort).
// The write is atomic (temp file + rename) so a concurrent
// removeCredFile can never observe a half-written cache.
func (c *Client) saveCredFile(cs *auth.ClientSession) {
	if c.opts.CredFile == "" || cs == nil {
		return
	}
	cc := credCache{
		Ticket:  base64.StdEncoding.EncodeToString(cs.Ticket),
		Key:     base64.StdEncoding.EncodeToString(cs.Key[:]),
		Expires: cs.Expires.Unix(),
	}
	b, err := json.Marshal(&cc)
	if err != nil {
		return
	}
	dir := filepath.Dir(c.opts.CredFile)
	if err := os.MkdirAll(dir, 0o700); err != nil && dir != "." {
		return
	}
	tmp, err := os.CreateTemp(dir, "cred-*.tmp")
	if err != nil {
		log.Printf("client: could not persist credential (%v)", err)
		return
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(b)
	_ = tmp.Chmod(0o600)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmpName)
		log.Printf("client: could not persist credential (%v)", werr)
		return
	}
	if err := os.Rename(tmpName, c.opts.CredFile); err != nil {
		_ = os.Remove(tmpName)
		log.Printf("client: could not persist credential (%v)", err)
	}
}

// removeCredFile deletes a consumed credential cache file.
func (c *Client) removeCredFile() {
	if c.opts.CredFile == "" {
		return
	}
	_ = os.Remove(c.opts.CredFile)
}
