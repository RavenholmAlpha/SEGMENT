package tunnel

import (
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"

	"segment/internal/auth"
	"segment/internal/h2x"
	"segment/internal/segment"
)

// Client is the client-side tunnel over one h2 connection. It exposes
// tunneled TCP connections and UDP flows to the local ingress.
type Client struct {
	h2c       *h2x.Conn
	authC     *auth.Client
	cs        *auth.ClientSession
	connNonce []byte
	sess      *segment.Session

	mu            sync.Mutex
	control       *h2x.Stream
	resuming      bool
	resumeCh      chan error
	keepaliveStop chan struct{}
	closed        bool
	onFail        chan struct{}
	authority     string
}

// Dial establishes the h2 connection and opens the control stream. If
// cs is a still-valid cached credential, the client immediately sends
// the 0-RTT AUTH_RESUME and the connection is usable right away; the
// caller should still call WaitReady to confirm the resume. authority
// is the Host/SNI used in request headers.
func Dial(tlsConn net.Conn, cfg h2x.Config, authC *auth.Client, cs *auth.ClientSession, authority string) (*Client, error) {
	h2c, err := h2x.ClientConn(tlsConn, cfg)
	if err != nil {
		return nil, err
	}
	connNonce := make([]byte, segment.ConnNonceLen)
	if _, err := rand.Read(connNonce); err != nil {
		return nil, err
	}
	sess, err := segment.NewSession(connNonce)
	if err != nil {
		return nil, err
	}

	c := &Client{
		h2c:           h2c,
		authC:         authC,
		cs:            cs,
		connNonce:     connNonce,
		sess:          sess,
		resumeCh:      make(chan error, 1),
		keepaliveStop: make(chan struct{}),
		onFail:        make(chan struct{}),
		authority:     authority,
	}

	control, err := h2c.NewStream(c.tunnelHeaders("/videos/channel/sessions-0.m3u8"), false)
	if err != nil {
		return nil, err
	}
	control.Pad = PadLen
	c.control = control

	codec := NewCodec(control, sess, segment.DirClientToServer, segment.DirServerToClient)
	if cs != nil {
		if !cs.Valid(time.Now()) {
			c.cs = nil // expired: force full handshake
		}
	}
	if c.cs != nil {
		// 0-RTT resume: prove possession of the cached session key and
		// start encrypting data streams immediately.
		if err := sess.Establish(c.cs.Key[:]); err != nil {
			return nil, err
		}
		payload, err := auth.BuildResumePayload(c.cs, connNonce)
		if err != nil {
			return nil, err
		}
		if err := codec.WriteFrame(segment.FrameAuthResume, 0, payload, 0); err != nil {
			return nil, err
		}
		c.resuming = true
		go c.waitResumeAck(codec)
	}
	go c.keepaliveLoop(codec)
	return c, nil
}

// waitResumeAck watches the control stream for the server's FRAME_ACK
// confirming the resumed session.
func (c *Client) waitResumeAck(codec *Codec) {
	f, err := codec.ReadFrame()
	if err != nil {
		c.resumeCh <- err
		return
	}
	if f.Type == segment.FrameAck {
		c.resumeCh <- nil
		return
	}
	c.resumeCh <- errors.New("tunnel: unexpected frame on control stream")
}

// keepaliveLoop sends FRAME_KEEPALIVE on the control stream; the
// server replies with FRAME_ACK (keepalive state machine).
func (c *Client) keepaliveLoop(codec *Codec) {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.keepaliveStop:
			return
		case <-t.C:
			ts := time.Now().UnixMilli()
			if err := codec.WriteFrame(segment.FrameKeepalive, 0, segment.BuildKeepalivePayload(uint64(ts)), 0); err != nil {
				return
			}
			// Read the ACK (1 frame) so the control stream stays tidy.
			if _, err := codec.ReadFrame(); err != nil {
				return
			}
		}
	}
}

// WaitReady returns once the session is confirmed: immediately for the
// full-handshake path, or after the resume ACK (or its failure). A
// non-nil error means the resume failed and the caller must redial and
// complete the full handshake instead.
func (c *Client) WaitReady(timeout time.Duration) error {
	if !c.resuming {
		return nil
	}
	select {
	case err := <-c.resumeCh:
		return err
	case <-time.After(timeout):
		return errors.New("tunnel: resume confirmation timed out")
	}
}

// Establish performs the full PSK handshake (POST /api/v1/telemetry)
// and caches the returned credential for future 0-RTT resumes.
func (c *Client) Establish() error {
	hdr, body, err := c.authC.BuildAuthRequest(c.connNonce)
	if err != nil {
		return err
	}
	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: c.authority},
		{Name: ":path", Value: "/api/v1/telemetry"},
		{Name: "content-type", Value: "application/json"},
		{Name: "user-agent", Value: ua},
		{Name: "x-sg-c", Value: hdr},
	}
	st, err := c.h2c.NewStream(hdrs, false)
	if err != nil {
		return err
	}
	if err := st.WriteData(body, true); err != nil {
		return err
	}
	resp, err := readAll(st)
	if err != nil {
		return err
	}
	cs, err := auth.SessionFromResponse(resp, 24*time.Hour)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cs = cs
	c.mu.Unlock()
	return c.sess.Establish(cs.Key[:])
}

// OpenTCP opens a tunneled TCP connection to the target.
func (c *Client) OpenTCP(addr string, port uint16) (*Conn, error) {
	st, err := c.h2c.NewStream(c.tunnelHeaders(segPath()), false)
	if err != nil {
		return nil, err
	}
	st.Pad = PadLen
	codec := NewCodec(st, c.sess, segment.DirClientToServer, segment.DirServerToClient)
	if err := codec.WriteFrame(segment.FrameOpen, 0, segment.BuildOpenPayload(addr, port), 0); err != nil {
		return nil, err
	}
	return NewConn(codec), nil
}

// OpenUDP opens a tunneled UDP flow to the target. Each WriteTo call
// sends one datagram; ReadFrom returns one response datagram.
func (c *Client) OpenUDP(addr string, port uint16) (*UDPCh, error) {
	st, err := c.h2c.NewStream(c.tunnelHeaders(segPath()), false)
	if err != nil {
		return nil, err
	}
	st.Pad = PadLen
	codec := NewCodec(st, c.sess, segment.DirClientToServer, segment.DirServerToClient)
	if err := codec.WriteFrame(segment.FrameOpen, segment.FlagUDP, segment.BuildOpenPayload(addr, port), 0); err != nil {
		return nil, err
	}
	return &UDPCh{codec: codec}, nil
}

// Close tears down the client connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.keepaliveStop)
	c.mu.Unlock()
	c.h2c.GoAway()
	return nil
}

// ClientSession returns the cached resumable credential (nil before
// any handshake).
func (c *Client) ClientSession() *auth.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs
}

// Done is closed when the underlying h2 connection dies (network error,
// GOAWAY, close). Consumers use it to detect tunnel loss and reconnect.
func (c *Client) Done() <-chan struct{} {
	return c.h2c.Done()
}

// ErrDgramTooBig is returned when a UDP datagram exceeds the tunnel's
// single-frame limit (one FRAME_DATA = one datagram; see DataChunk).
// Real-world UDP traffic (DNS, QUIC, gaming, media signalling) stays
// well below this limit.
var ErrDgramTooBig = errors.New("tunnel: UDP datagram exceeds " + strconv.Itoa(DataChunk) + " bytes")

// UDPCh is one tunneled UDP flow.
type UDPCh struct {
	codec *Codec
	once  sync.Once
}

// WriteTo sends one datagram.
func (u *UDPCh) WriteTo(dgram []byte) error {
	if len(dgram) > DataChunk {
		return ErrDgramTooBig
	}
	return u.codec.WriteFrame(segment.FrameData, 0, segment.BuildDataPayload(dgram), 0)
}

// ReadFrom returns one response datagram.
func (u *UDPCh) ReadFrom(buf []byte) (int, error) {
	for {
		f, err := u.codec.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch f.Type {
		case segment.FrameData:
			d, err := segment.ParseDataPayload(f.Payload)
			if err != nil {
				return 0, err
			}
			return copy(buf, d), nil
		case segment.FrameClose:
			return 0, net.ErrClosed
		}
	}
}

// Close terminates the UDP flow.
func (u *UDPCh) Close() error {
	u.once.Do(func() {
		_ = u.codec.WriteFrame(segment.FrameClose, 0, segment.BuildClosePayload(0), 0)
		_ = u.codec.st.CloseSend()
	})
	return nil
}

var ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// tunnelHeaders builds a canonical Chrome 120 media-segment request:
// MSE/HLS segment fetches send exactly this header family (sec-fetch-
// dest=empty, sec-fetch-mode=cors, priority=u=1,i, accept=*/*,
// accept-encoding=identity, range on seek). The three marker values
// switch the stream into tunnel mode server-side (see server.go); no
// custom header name appears on the wire.
func (c *Client) tunnelHeaders(path string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: c.authority},
		{Name: ":path", Value: path},
		{Name: "accept", Value: "*/*"},
		{Name: "accept-encoding", Value: "identity"},
		{Name: "accept-language", Value: "en-US,en;q=0.9"},
		{Name: "priority", Value: "u=1, i"},
		{Name: "range", Value: "bytes=0-"},
		{Name: "sec-ch-ua", Value: `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
		{Name: "sec-ch-ua-mobile", Value: "?0"},
		{Name: "sec-ch-ua-platform", Value: `"Windows"`},
		{Name: "sec-fetch-dest", Value: "empty"},
		{Name: "sec-fetch-mode", Value: "cors"},
		{Name: "sec-fetch-site", Value: "same-origin"},
		{Name: "user-agent", Value: ua},
	}
}

var segCounter atomic.Uint64

// segPath produces a plausible per-stream media path (safe for
// concurrent use across many tunnel connections).
func segPath() string {
	n := segCounter.Add(1) - 1
	return "/videos/channel/seg-" + itoa64(n%1000) + ".m4s"
}

func itoa64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
