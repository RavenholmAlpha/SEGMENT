// Package server glues the tunnel server-side pieces together and
// runs the caddy-like listener.
package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"

	"segment/internal/auth"
	"segment/internal/fakesite"
	"segment/internal/h2x"
	"segment/internal/tunnel"
)

// Options configures one server instance.
type Options struct {
	Auth     *auth.Server
	Dial     tunnel.DialFunc // outbound dialer (defaults to net.Dial)
	Site     *fakesite.Site  // fake video site (nil -> default)
	Pacing   tunnel.Pacing   // outbound media pacing (zero -> disabled)
	H2Config h2x.Config      // zero -> DefaultConfig
}

// handshakeTimeout bounds a client's TLS handshake: a peer that sends
// a partial ClientHello and stalls (slowloris) must not pin a
// goroutine and fd forever.
const handshakeTimeout = 10 * time.Second

// Accept handles one fronted TLS connection, routing by the negotiated
// ALPN protocol: h2 connections may become tunnels; everything else
// (http/1.1 clients, probes) is served the fake site so ordinary
// browsing always succeeds.
func Accept(nc net.Conn, opts Options) {
	// A panic in any downstream goroutine this function spawns (or in
	// the synchronous http/1.1 path) must degrade one connection, not
	// take down the whole fronting server.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("server: recovered from panic handling connection: %v", r)
			_ = nc.Close()
		}
	}()
	if opts.Dial == nil {
		opts.Dial = net.Dial
	}
	if opts.Site == nil {
		opts.Site = fakesite.DefaultSite()
	}
	if opts.H2Config.Settings.MaxConcurrentStreams == 0 {
		opts.H2Config = h2x.DefaultConfig()
	}

	if tlsConn, ok := nc.(*tls.Conn); ok {
		_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tlsConn.Handshake(); err != nil {
			_ = nc.Close()
			return
		}
		_ = nc.SetDeadline(time.Time{}) // clear; h2 connections are long-lived
		switch tlsConn.ConnectionState().NegotiatedProtocol {
		case "h2":
			// Tunnel-capable fronting layer below.
		default:
			opts.Site.ServeHTTP11(nc)
			return
		}
	}

	h2c, err := h2x.ServerConn(nc, opts.H2Config, func(c *h2x.Conn, st *h2x.Stream) {
		// Runs on an h2x-spawned goroutine per stream; keep a stream
		// handler panic from killing the process.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("server: recovered from panic on stream %d: %v", st.ID(), r)
				_ = st.Reset(0x2) // ErrCodeStreamClosed
			}
		}()
		cs := tunnel.StateFor(c, opts.Auth, opts.Dial, opts.Pacing, opts.Site.Serve)
		if err := cs.HandleStream(st); err == tunnel.ErrFakeSite {
			go opts.Site.Serve(st)
		}
	})
	if err != nil {
		_ = nc.Close()
		return
	}
	<-h2c.Done()
	tunnel.Release(h2c)
}

// Serve accepts TCP/TLS connections on ln until it errors. Transient
// accept failures (e.g. EMFILE) are retried with backoff instead of
// tearing down the whole listener.
func Serve(ln net.Listener, opts Options) error {
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				}
				time.Sleep(backoff)
				if backoff < 2*time.Second {
					backoff *= 2
				}
				continue
			}
			return err
		}
		backoff = 0
		go Accept(nc, opts)
	}
}

// TLSListener wraps a raw listener in TLS with ALPN h2. TLS 1.2 is
// accepted so the fake site serves legacy clients and middleboxes like
// any real video CDN; TLS 1.3 is preferred via Go's default
// configuration.
func TLSListener(ln net.Listener, cert tls.Certificate) net.Listener {
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	})
}

// SelfSignedCert generates an ephemeral self-signed certificate for
// development and integration tests.
func SelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "video.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"video.example.com", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
