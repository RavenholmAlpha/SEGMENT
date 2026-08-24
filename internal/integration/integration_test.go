// Package integration runs the full Segment stack end to end over real
// TCP/TLS sockets on loopback: fake-site behavior, full handshake,
// SOCKS5 TCP + UDP ASSOCIATE, ticket resume, and ticket single-use.
package integration

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"segment/internal/auth"
	"segment/internal/client"
	"segment/internal/fakesite"
	"segment/internal/h2x"
	"segment/internal/server"
	"segment/internal/tunnel"
)

const (
	pskStr     = "integration-secret-psk-0123456789abcdef"
	siteHost   = "video.example.com"
	testMsgTCP = "ping-through-segment"
	testMsgUDP = "udp-roundtrip"
)

func TestEndToEnd(t *testing.T) {
	te := startTCPEcho(t)
	ue := startUDPEcho(t)
	teHost, tePort := splitAddr(te)
	ueHost, uePort := splitAddr(ue)

	authSrv, err := auth.NewServer([]byte(pskStr), time.Hour, 30*time.Second, nil)
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
	serverAddr := raw.Addr().String()
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv})
	t.Cleanup(func() { _ = raw.Close() })

	t.Run("fake-site", func(t *testing.T) {
		status, body := getFake(t, serverAddr, "/")
		if status != "200" || !strings.Contains(string(body), "StreamHub") {
			t.Fatalf("index: status=%s body=%q", status, body)
		}
		status, body = getFake(t, serverAddr, "/videos/alpha/index.m3u8")
		if status != "200" || !strings.Contains(string(body), "#EXTM3U") {
			t.Fatalf("manifest: status=%s body=%q", status, body)
		}
		_, seg1 := getFake(t, serverAddr, "/videos/alpha/seg-0.ts")
		_, seg2 := getFake(t, serverAddr, "/videos/alpha/seg-0.ts")
		if len(seg1) == 0 || len(seg1) != len(seg2) || string(seg1) != string(seg2) {
			t.Fatalf("segment not deterministic (%d vs %d bytes)", len(seg1), len(seg2))
		}
		status, _ = getFake(t, serverAddr, "/does/not/exist")
		if status != "404" {
			t.Fatalf("404 route: status=%s", status)
		}
	})

	cc, err := client.NewWithPSK(client.Options{
		Server:   serverAddr,
		SNI:      siteHost,
		Insecure: true,
	}, []byte(pskStr))
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.Connect(); err != nil {
		t.Fatalf("connect (full handshake): %v", err)
	}
	cred := cc.Credential()
	if cred == nil {
		t.Fatal("full handshake did not yield a resumable credential")
	}

	ln, err := cc.SOCKSListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	socksAddr := ln.Addr().String()

	t.Run("socks5-tcp", func(t *testing.T) {
		sc, err := socksConnect(socksAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer sc.Close()
		if err := socksRequest(sc, 1, teHost, tePort); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Write([]byte(testMsgTCP)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(testMsgTCP))
		_ = sc.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(sc, got); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(got) != testMsgTCP {
			t.Fatalf("tcp echo mismatch: got %q", got)
		}
	})

	t.Run("socks5-udp", func(t *testing.T) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		sc, err := socksConnect(socksAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer sc.Close()
		bound, err := socksUDPAssociate(sc)
		if err != nil {
			t.Fatal(err)
		}
		dgram := append(udpHeader(ueHost, uePort), []byte(testMsgUDP)...)
		if _, err := uc.WriteToUDP(dgram, bound); err != nil {
			t.Fatal(err)
		}
		_ = uc.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := uc.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read udp reply: %v", err)
		}
		_, _, payload, ok := parseUDPDatagram(buf[:n])
		if !ok {
			t.Fatalf("bad reply datagram: %x", buf[:n])
		}
		if string(payload) != testMsgUDP {
			t.Fatalf("udp echo mismatch: got %q", payload)
		}
	})

	authC, err := auth.NewClient([]byte(pskStr))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ticket-resume", func(t *testing.T) {
		cli := dialResume(t, serverAddr, authC, cred)
		defer cli.Close()
		rc, err := cli.OpenTCP(teHost, tePort)
		if err != nil {
			t.Fatal(err)
		}
		msg := "resume-echo"
		if _, err := rc.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(rc, got); err != nil {
			t.Fatalf("resumed conn read: %v", err)
		}
		if string(got) != msg {
			t.Fatalf("resumed conn echo mismatch: got %q", got)
		}
	})

	t.Run("ticket-single-use", func(t *testing.T) {
		// The same ticket must be rejected on a second use.
		if err := dialResumeExpectFail(serverAddr, authC, cred, 5*time.Second); err == nil {
			t.Fatal("replayed ticket was accepted")
		}
	})

	t.Run("wrong-key-resume-rejected", func(t *testing.T) {
		bad := *cred
		bad.Key[0] ^= 0xFF
		if err := dialResumeExpectFail(serverAddr, authC, &bad, 5*time.Second); err == nil {
			t.Fatal("resume with wrong key was accepted")
		}
	})
}

// TestUnauthenticatedMarkerUsesFakeSite ensures even stream 1, when carrying
// only media markers and no established Segment session, behaves exactly like
// a normal media fetch.
func TestUnauthenticatedMarkerUsesFakeSite(t *testing.T) {
	serverAddr := startSegmentServer(t)
	tlsConn := dialTLS(t, serverAddr)
	defer tlsConn.Close()
	h2c, err := h2x.ClientConn(tlsConn, h2x.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.GoAway()

	marked, err := h2c.NewStream(mediaHeaders("/videos/alpha/seg-0.m4s"), true)
	if err != nil {
		t.Fatal(err)
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
	status, body := readH2Response(t, marked)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if status != "200" {
		t.Fatalf("media marker status = %s, want fake-site 200", status)
	}
	if len(body) == 0 {
		t.Fatal("media marker received an empty fake-site body")
	}
}

// TestInvalidAuthPostUsesFakeSite ensures both resume-shaped requests without
// a proof header and full-auth-shaped requests with an invalid proof receive
// the configured site's normal 404 page rather than a distinctive protocol
// authentication status.
func TestInvalidAuthPostUsesFakeSite(t *testing.T) {
	site := &fakesite.Site{
		Title:          "Configured probe cover",
		SegmentSeconds: 6,
		SegmentSizeKB:  []int{256},
	}
	serverAddr := startSegmentServer(t, site)

	tests := []struct {
		name  string
		proof string
	}{
		{name: "missing-proof-resume-shape"},
		{name: "present-invalid-full-auth-proof", proof: "definitely-not-a-valid-proof"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tlsConn := dialTLS(t, serverAddr)
			defer tlsConn.Close()
			h2c, err := h2x.ClientConn(tlsConn, h2x.DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer h2c.GoAway()

			hdrs := fakeHeaders("POST", "/api/v1/telemetry")
			if tc.proof != "" {
				hdrs = append(hdrs, hpack.HeaderField{Name: "x-sg-c", Value: tc.proof})
			}
			st, err := h2c.NewStream(hdrs, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.WriteData([]byte("not valid Segment authentication"), true); err != nil {
				t.Fatal(err)
			}
			assertConfiguredAuthCover(t, st)
		})
	}
}

// TestReplayedResumeUsesFakeSite verifies that a valid-but-consumed ticket is
// indistinguishable from an ordinary request at the HTTP boundary. The auth
// package separately asserts the exact ErrReplay classification internally.
func TestReplayedResumeUsesFakeSite(t *testing.T) {
	site := &fakesite.Site{
		Title:          "Configured replay cover",
		SegmentSeconds: 6,
		SegmentSizeKB:  []int{256},
	}
	serverAddr := startSegmentServer(t, site)
	authC, err := auth.NewClient([]byte(pskStr))
	if err != nil {
		t.Fatal(err)
	}

	fullTLS := dialTLS(t, serverAddr)
	full, err := tunnel.Dial(fullTLS, h2x.DefaultConfig(), authC, nil, siteHost)
	if err != nil {
		t.Fatal(err)
	}
	if err := full.Establish(); err != nil {
		t.Fatal(err)
	}
	cred := full.ClientSession()
	if cred == nil {
		t.Fatal("full handshake did not return a resumable credential")
	}
	_ = full.Close()
	_ = fullTLS.Close()

	resumeTLS := dialTLS(t, serverAddr)
	resumed, err := tunnel.Dial(resumeTLS, h2x.DefaultConfig(), authC, cred, siteHost)
	if err != nil {
		t.Fatal(err)
	}
	_ = resumed.Close()
	_ = resumeTLS.Close()

	replayBody, err := auth.BuildResumePayload(cred, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	replayTLS := dialTLS(t, serverAddr)
	defer replayTLS.Close()
	h2c, err := h2x.ClientConn(replayTLS, h2x.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.GoAway()
	st, err := h2c.NewStream(fakeHeaders("POST", "/api/v1/telemetry"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteData(replayBody, true); err != nil {
		t.Fatal(err)
	}
	status, body := readH2Response(t, st)
	if status != "404" {
		t.Fatalf("replayed resume status = %s, want fake-site 404", status)
	}
	if !strings.Contains(string(body), "Configured replay cover") {
		t.Fatalf("replayed resume body is not the configured fake-site page: %q", body)
	}
}

func assertConfiguredAuthCover(t *testing.T, st *h2x.Stream) {
	t.Helper()
	status, body := readH2Response(t, st)
	if status != "404" {
		t.Fatalf("invalid auth status = %s, want fake-site 404", status)
	}
	if !strings.Contains(string(body), "Configured probe cover") {
		t.Fatalf("invalid auth body is not the fake-site 404 page: %q", body)
	}
}

// --- echo servers ---------------------------------------------------

func startTCPEcho(tb testing.TB) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(tb testing.TB) string {
	// udp4 for a predictable 127.0.0.1 address (dual-stack "udp"
	// reports an IPv6 wildcard on some platforms).
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], src)
		}
	}()
	return pc.LocalAddr().String()
}

func splitAddr(a string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(a)
	if err != nil {
		panic(err)
	}
	p, _ := strconv.Atoi(portStr)
	return host, uint16(p)
}

func startSegmentServer(t *testing.T, sites ...*fakesite.Site) string {
	t.Helper()
	authSrv, err := auth.NewServer([]byte(pskStr), time.Hour, 30*time.Second, nil)
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
	var site *fakesite.Site
	if len(sites) > 0 {
		site = sites[0]
	}
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv, Site: site})
	t.Cleanup(func() { _ = raw.Close() })
	return raw.Addr().String()
}

// --- fake-site probe ------------------------------------------------

// getFake speaks h2 directly (no tunnel marker) and returns the
// response status and body as the fake site would serve them.
func getFake(t *testing.T, addr, path string) (string, []byte) {
	t.Helper()
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc = tls.Client(tc, &tls.Config{
		InsecureSkipVerify: true, // self-signed test cert
		NextProtos:         []string{"h2"},
		ServerName:         siteHost,
	})
	if err := tc.(*tls.Conn).Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	h2c, err := h2x.ClientConn(tc, h2x.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	st, err := h2c.NewStream(fakeHeaders("GET", path), true)
	if err != nil {
		t.Fatal(err)
	}
	return readH2Response(t, st)
}

func fakeHeaders(method, path string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: siteHost},
		{Name: ":path", Value: path},
		{Name: "user-agent", Value: "Mozilla/5.0 (test)"},
	}
}

func mediaHeaders(path string) []hpack.HeaderField {
	hdr := fakeHeaders("GET", path)
	return append(hdr,
		hpack.HeaderField{Name: "sec-fetch-dest", Value: "empty"},
		hpack.HeaderField{Name: "sec-fetch-mode", Value: "cors"},
		hpack.HeaderField{Name: "priority", Value: "u=1, i"},
	)
}

func readH2Response(t *testing.T, st *h2x.Stream) (string, []byte) {
	t.Helper()
	var body []byte
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		body = append(body, p...)
		if end {
			break
		}
	}
	status := "0"
	for _, h := range st.Headers() {
		if h.Name == ":status" {
			status = h.Value
		}
	}
	return status, body
}

// --- tunnel dial helpers -------------------------------------------

func dialTLS(tb testing.TB, addr string) *tls.Conn {
	tb.Helper()
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		tb.Fatal(err)
	}
	tlsConn := tls.Client(tc, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         siteHost,
	})
	if err := tlsConn.Handshake(); err != nil {
		tb.Fatal(err)
	}
	return tlsConn
}

func dialResume(tb testing.TB, addr string, authC *auth.Client, cred *auth.ClientSession) *tunnel.Client {
	tb.Helper()
	tlsConn := dialTLS(tb, addr)
	cli, err := tunnel.Dial(tlsConn, h2x.DefaultConfig(), authC, cred, siteHost)
	if err != nil {
		tb.Fatal(err)
	}
	if err := cli.WaitReady(5 * time.Second); err != nil {
		_ = cli.Close()
		tb.Fatalf("resume was not confirmed: %v", err)
	}
	return cli
}

func dialResumeExpectFail(addr string, authC *auth.Client, cred *auth.ClientSession, timeout time.Duration) error {
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	tlsConn := tls.Client(tc, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         siteHost,
	})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	cli, err := tunnel.Dial(tlsConn, h2x.DefaultConfig(), authC, cred, siteHost)
	if err != nil {
		return err
	}
	wErr := cli.WaitReady(timeout)
	_ = cli.Close()
	return wErr
}

// --- minimal SOCKS5 client -----------------------------------------

func socksConnect(addr string) (net.Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		_ = c.Close()
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		_ = c.Close()
		return nil, err
	}
	if rep[0] != 5 || rep[1] != 0 {
		_ = c.Close()
		return nil, fmt.Errorf("no-auth not accepted: %v", rep)
	}
	return c, nil
}

func socksRequest(conn net.Conn, cmd byte, dst string, port uint16) error {
	_, err := socksRequestReply(conn, cmd, dst, port)
	return err
}

// socksRequestReply sends one SOCKS5 request and reads its 10-byte
// reply (validated version/reply code).
func socksRequestReply(conn net.Conn, cmd byte, dst string, port uint16) ([]byte, error) {
	var req []byte
	req = append(req, 5, cmd, 0)
	if ip := net.ParseIP(dst); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 3, byte(len(dst)))
		req = append(req, dst...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return nil, err
	}
	if rep[0] != 5 {
		return nil, errors.New("socks5: bad reply version")
	}
	if rep[1] != 0 {
		return nil, fmt.Errorf("socks5: request failed (rep=%d)", rep[1])
	}
	return rep, nil
}

func socksUDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	rep, err := socksRequestReply(conn, 3, "0.0.0.0", 0)
	if err != nil {
		return nil, err
	}
	if rep[0] != 5 || rep[1] != 0 || rep[3] != 1 {
		return nil, fmt.Errorf("socks5: bad associate reply %v", rep)
	}
	port := binary.BigEndian.Uint16(rep[8:10])
	return &net.UDPAddr{IP: net.IPv4(rep[4], rep[5], rep[6], rep[7]), Port: int(port)}, nil
}

func udpHeader(dst string, port uint16) []byte {
	var b []byte
	b = append(b, 0, 0, 0) // RSV FRAG
	if ip := net.ParseIP(dst); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 3, byte(len(dst)))
		b = append(b, dst...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(b, p[:]...)
}

// parseUDPDatagram parses the SOCKS5 UDP datagram header and payload.
func parseUDPDatagram(b []byte) (string, uint16, []byte, bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", 0, nil, false
	}
	i := 4
	switch b[3] {
	case 1:
		if len(b) < i+4 {
			return "", 0, nil, false
		}
		i += 4
	case 3:
		if len(b) < i+1 {
			return "", 0, nil, false
		}
		i += 1 + int(b[i])
	case 4:
		if len(b) < i+16 {
			return "", 0, nil, false
		}
		i += 16
	default:
		return "", 0, nil, false
	}
	if len(b) < i+2 {
		return "", 0, nil, false
	}
	return "", binary.BigEndian.Uint16(b[i : i+2]), b[i+2:], true
}

// TestRelayUnblocksWhenPeerIdleAndSocketCloses guards the relay double
// pump: when the target socket closes while the tunnel peer stays idle
// (no frames, no RST), the server relay must still tear the stream down
// (CloseRead wakes the blocked reader; FRAME_CLOSE + END_STREAM reach
// the client) instead of deadlocking in wg.Wait() and leaving the
// client's Read blocked forever.
func TestRelayUnblocksWhenPeerIdleAndSocketCloses(t *testing.T) {
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
				_, _ = c.Write([]byte("bye"))
			}(conn)
		}
	}()
	targetHost, targetPort := splitAddr(ln.Addr().String())

	authSrv, err := auth.NewServer([]byte(pskStr), time.Hour, 30*time.Second, nil)
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
	serverAddr := raw.Addr().String()
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv})
	t.Cleanup(func() { _ = raw.Close() })

	cc, err := client.NewWithPSK(client.Options{
		Server:   serverAddr,
		SNI:      siteHost,
		Insecure: true,
	}, []byte(pskStr))
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	conn, err := cc.OpenTCPRaw(targetHost, targetPort)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Peer data arrives; then the peer socket closes while this stream
	// stays idle (no more frames from the client).
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read peer data: %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("peer data mismatch: %q", buf)
	}
	// The next read must terminate promptly (EOF or reset), not hang.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read after peer close returned data")
	}
	t.Logf("read after peer close returned: %v", err)
}

// TestUDPHighRateDelivers guards the UDP reply path: sustained
// high-rate egress answers must be delivered to the SOCKS client (a
// sampled, time-ticked reply pump would deliver a handful per tick and
// back-pressure the tunnel, freezing the datagram path).
func TestUDPHighRateDelivers(t *testing.T) {
	ue := startUDPEcho(t)
	ueHost, uePort := splitAddr(ue)

	authSrv, err := auth.NewServer([]byte(pskStr), time.Hour, 30*time.Second, nil)
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
	serverAddr := raw.Addr().String()
	go server.Serve(server.TLSListener(raw, cert), server.Options{Auth: authSrv})
	t.Cleanup(func() { _ = raw.Close() })

	cc, err := client.NewWithPSK(client.Options{
		Server:   serverAddr,
		SNI:      siteHost,
		Insecure: true,
	}, []byte(pskStr))
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	ln, err := cc.SOCKSListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctrl, err := socksConnect(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	relay, err := socksUDPAssociate(ctrl)
	if err != nil {
		t.Fatal(err)
	}

	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	send := func(n int) {
		b := udpHeader(ueHost, uePort)
		b = append(b, testMsgUDP...)
		for i := 0; i < n; i++ {
			_, _ = pc.WriteToUDP(b, relay)
		}
	}
	// ~330 datagrams/s for ~2.4s: far above the old sampled pump's
	// delivery budget; every answer must still come back promptly.
	const burstPerTick = 100
	deadline := time.Now().Add(3 * time.Second)
	var sent, recv int
	for time.Now().Before(deadline) {
		send(burstPerTick)
		sent += burstPerTick
		// Collect whatever returned meanwhile.
		_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if _, _, payload, ok := parseUDPDatagram(buf[:n]); ok && string(payload) == testMsgUDP {
				recv++
			}
		}
	}
	t.Logf("udp high-rate: sent=%d recv=%d", sent, recv)
	if recv*10 < sent*4 { // tolerate some loopback jitter, never 60% loss
		t.Fatalf("udp high-rate starvation: sent=%d recv=%d", sent, recv)
	}
	// The tunnel itself must still be healthy: a final datagram must
	// round-trip promptly (echo replies travel the whole tunnel).
	send(1)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	var lastErr error
	for {
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			lastErr = err
			break
		}
		if _, _, payload, ok := parseUDPDatagram(buf[:n]); ok && string(payload) == testMsgUDP {
			return
		}
	}
	t.Fatalf("tunnel dead after UDP burst: %v", lastErr)
}
