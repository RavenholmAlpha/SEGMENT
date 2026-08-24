package integration

import (
	"io"
	"net"
	"testing"
	"time"

	"segment/internal/auth"
	"segment/internal/client"
	"segment/internal/h2x"
	"segment/internal/server"
	"segment/internal/tunnel"
)

// benchSetup starts a Segment server + echo server and returns a fully
// connected tunnel client (full handshake) plus the client auth handle
// and the echo target.
func benchSetup(b *testing.B) (*client.Client, *auth.Client, string, uint16) {
	return benchSetupPaced(b, tunnel.Pacing{})
}

// benchSetupPaced is benchSetup with an explicit pacing configuration.
func benchSetupPaced(b *testing.B, pacing tunnel.Pacing) (*client.Client, *auth.Client, string, uint16) {
	b.Helper()
	te := startTCPEcho(b)
	teHost, tePort := splitAddr(te)

	authSrv, err := auth.NewServer([]byte(pskStr), time.Hour, 30*time.Second, nil)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := server.SelfSignedCert()
	if err != nil {
		b.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	serverAddr := raw.Addr().String()
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv, Pacing: pacing})
	b.Cleanup(func() { _ = raw.Close() })

	cc, err := client.NewWithPSK(client.Options{
		Server:   serverAddr,
		SNI:      siteHost,
		Insecure: true,
	}, []byte(pskStr))
	if err != nil {
		b.Fatal(err)
	}
	if err := cc.Connect(); err != nil {
		b.Fatal(err)
	}
	authC, err := auth.NewClient([]byte(pskStr))
	if err != nil {
		b.Fatal(err)
	}
	return cc, authC, teHost, tePort
}

// BenchmarkTunnelPingPong16K measures one 16KB write + echo read per
// operation: the media-chunk pattern clients produce in practice.
func BenchmarkTunnelPingPong16K(b *testing.B) {
	cc, _, teHost, tePort := benchSetup(b)
	conn, err := cc.OpenTCPRaw(teHost, tePort)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, tunnel.DataChunk)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTunnelBulk1M streams 1MB through the tunnel per operation
// (write then read the echo), measuring sustained throughput.
func BenchmarkTunnelBulk1M(b *testing.B) {
	cc, _, teHost, tePort := benchSetup(b)
	conn, err := cc.OpenTCPRaw(teHost, tePort)
	if err != nil {
		b.Fatal(err)
	}
	const chunk = tunnel.DataChunk
	const total = 1 << 20
	buf := make([]byte, chunk)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for sent := 0; sent < total; sent += chunk {
			if _, err := conn.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		for rcvd := 0; rcvd < total; rcvd += chunk {
			if _, err := io.ReadFull(conn, buf); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkTunnelBulk1MPaced is the same bulk test with the
// production media pacing enabled (256 KB bursts, 2-8 ms pauses).
func BenchmarkTunnelBulk1MPaced(b *testing.B) {
	cc, _, teHost, tePort := benchSetupPaced(b, tunnel.DefaultPacing())
	conn, err := cc.OpenTCPRaw(teHost, tePort)
	if err != nil {
		b.Fatal(err)
	}
	const chunk = tunnel.DataChunk
	const total = 1 << 20
	buf := make([]byte, chunk)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for sent := 0; sent < total; sent += chunk {
			if _, err := conn.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		for rcvd := 0; rcvd < total; rcvd += chunk {
			if _, err := io.ReadFull(conn, buf); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkResumeHandshake measures the ticket-resume path only: TCP +
// TLS + h2 + authentication POST confirmation. Because tickets are
// single-use, each iteration first completes a (unmeasured) full
// handshake to obtain a fresh credential.
func BenchmarkResumeHandshake(b *testing.B) {
	cc, authC, _, _ := benchSetup(b)
	cfg := h2x.DefaultConfig()
	serverAddr := cc.ServerAddr()
	opts := client.Options{Server: serverAddr, SNI: siteHost, Insecure: true}
	psk := []byte(pskStr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		fc, err := client.NewWithPSK(opts, psk)
		if err != nil {
			b.Fatal(err)
		}
		if err := fc.Connect(); err != nil { // full handshake (unmeasured)
			b.Fatal(err)
		}
		cred := fc.Credential()
		tlsConn := dialTLS(b, serverAddr)
		b.StartTimer()

		cli, err := tunnel.Dial(tlsConn, cfg, authC, cred, siteHost)
		if err != nil {
			b.Fatal(err)
		}
		if err := cli.WaitReady(2 * time.Second); err != nil {
			b.Fatal(err)
		}
		_ = cli.Close()
		b.StopTimer()
		_ = fc.Close()
	}
}

var _ = time.Now
