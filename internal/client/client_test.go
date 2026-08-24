package client

import (
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"segment/internal/auth"
	"segment/internal/server"
	"segment/internal/tunnel"
)

const testPSK = "test-psk-0123456789abcdef"

func startServer(t *testing.T) string {
	t.Helper()
	authSrv, err := auth.NewServer([]byte(testPSK), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := server.SelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv})
	t.Cleanup(func() { _ = raw.Close() })
	return raw.Addr().String()
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func portOf(t *testing.T, addr string) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(p)
}

func newTestClient(t *testing.T, addr, credFile string) *Client {
	t.Helper()
	c, err := NewWithPSK(Options{
		Server:   addr,
		SNI:      "video.example.com",
		Insecure: true,
		CredFile: credFile,
	}, []byte(testPSK))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitCurrent(t *testing.T, c *Client, not *tunnel.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cur := c.current()
		if cur != nil && cur != not {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("tunnel did not heal in time")
}

func TestReconnectAfterTunnelLoss(t *testing.T) {
	addr := startServer(t)
	echo := startEcho(t)
	c := newTestClient(t, addr, "")
	old := c.current()
	if old == nil {
		t.Fatal("no tunnel after connect")
	}

	conn, err := c.OpenTCPRaw("127.0.0.1", portOf(t, echo))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// Simulate a dead tunnel: supervision must heal it automatically.
	_ = old.Close()
	waitCurrent(t, c, old, 10*time.Second)
	if cur := c.current(); cur == old {
		t.Fatal("tunnel was not replaced")
	}

	conn2, err := c.OpenTCPRaw("127.0.0.1", portOf(t, echo))
	if err != nil {
		t.Fatalf("open after heal: %v", err)
	}
	defer conn2.Close()
	if _, err := conn2.Write([]byte("ping2")); err != nil {
		t.Fatal(err)
	}
	buf5 := make([]byte, 5)
	if _, err := io.ReadFull(conn2, buf5); err != nil {
		t.Fatal(err)
	}
	if string(buf5) != "ping2" {
		t.Fatalf("echo mismatch: %q", buf5)
	}
}

func TestCredentialPersistence(t *testing.T) {
	addr := startServer(t)
	credFile := t.TempDir() + "/cred.json"

	// First client: full handshake issues a fresh ticket, persisted.
	c1 := newTestClient(t, addr, credFile)
	if _, err := os.Stat(credFile); err != nil {
		t.Fatalf("credential file not written: %v", err)
	}
	_ = c1.Close()

	// Second client: loads the file and resumes by ticket without a full
	// handshake; ticket is single-use so the file is then removed.
	c2 := newTestClient(t, addr, credFile)
	if _, err := os.Stat(credFile); !os.IsNotExist(err) {
		t.Fatalf("credential file should be consumed and removed, err=%v", err)
	}
	if c2.Credential() != nil {
		t.Fatal("credential should be nil after a resume (single-use ticket)")
	}
	_ = c2.Close()
}

// TestCloseDuringReconnectInstallsNoGhostTunnel guards the Close-vs-
// reconnect race: closing while supervision is reconnecting must tear
// the half-built tunnel down rather than install an un-supervised ghost
// (which would leak the whole h2 connection and stay open after Close
// returned).
func TestCloseDuringReconnectInstallsNoGhostTunnel(t *testing.T) {
	addr := startServer(t)
	c := newTestClient(t, addr, "")
	old := c.current()
	if old == nil {
		t.Fatal("no tunnel after connect")
	}

	// Kill the tunnel; supervision enters its reconnect backoff.
	_ = old.Close()
	time.Sleep(50 * time.Millisecond)

	// Close mid-reconnect: must cancel the dial and leave no tunnel.
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // longer than any in-flight dial
	if cur := c.current(); cur != nil {
		t.Fatal("ghost tunnel installed after Close")
	}
	// A subsequent OpenTCPRaw must fail cleanly, not route anywhere.
	if conn, err := c.OpenTCPRaw("127.0.0.1", 1); err == nil {
		_ = conn.Close()
		t.Fatal("OpenTCPRaw succeeded after Close")
	}
}
