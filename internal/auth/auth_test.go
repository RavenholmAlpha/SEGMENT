package auth

import (
	"bytes"
	"testing"
	"time"

	"segment/internal/segment"
)

func newTestServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := NewServer([]byte("test-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func fullHandshake(tb testing.TB, c *Client, s *Server, connNonce []byte) *ClientSession {
	tb.Helper()
	hdr, body, err := c.BuildAuthRequest(connNonce)
	if err != nil {
		tb.Fatal(err)
	}
	sess, _, err := s.VerifyAuth(hdr, body)
	if err != nil {
		tb.Fatal(err)
	}
	ticket, err := s.IssueTicket(sess)
	if err != nil {
		tb.Fatal(err)
	}
	// Response body = ticket || sessionKey (as the server would send it).
	resp := append(append([]byte(nil), ticket...), sess.Key[:]...)
	cs, err := SessionFromResponse(resp, time.Hour)
	if err != nil {
		tb.Fatal(err)
	}
	return cs
}

func TestFullHandshakeAndResume(t *testing.T) {
	c, err := NewClient([]byte("test-psk-0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t)

	connNonce := make([]byte, segment.ConnNonceLen)
	for i := range connNonce {
		connNonce[i] = byte(i)
	}
	cs := fullHandshake(t, c, s, connNonce)

	// Ticket resume on a new connection (fresh connNonce).
	newNonce := bytes.Repeat([]byte{0xab}, segment.ConnNonceLen)
	payload, err := BuildResumePayload(cs, newNonce)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Resume(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sess.Key[:], cs.Key[:]) {
		t.Fatal("resumed session key mismatch")
	}
}

func TestResumeReplayRejected(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(t)
	cs := fullHandshake(t, c, s, make([]byte, segment.ConnNonceLen))

	payload, _ := BuildResumePayload(cs, bytes.Repeat([]byte{1}, segment.ConnNonceLen))
	if _, err := s.Resume(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resume(payload); err != ErrReplay {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}
}

func TestResumeBadHMAC(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(t)
	cs := fullHandshake(t, c, s, make([]byte, segment.ConnNonceLen))

	payload, _ := BuildResumePayload(cs, bytes.Repeat([]byte{1}, segment.ConnNonceLen))
	payload[len(payload)-1] ^= 0xff // corrupt the HMAC
	if _, err := s.Resume(payload); err != ErrBadResume {
		t.Fatalf("bad hmac: got %v, want ErrBadResume", err)
	}
}

func TestResumeUnknownSession(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(t)
	cs := fullHandshake(t, c, s, make([]byte, segment.ConnNonceLen))

	// A different server (fresh keySrv) cannot open our ticket.
	s2, _ := NewServer([]byte("test-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	payload, _ := BuildResumePayload(cs, bytes.Repeat([]byte{1}, segment.ConnNonceLen))
	if _, err := s2.Resume(payload); err != ErrBadTicket {
		t.Fatalf("foreign ticket: got %v, want ErrBadTicket", err)
	}
	// Same server, but a fake ticket of the right size.
	fake := bytes.Repeat([]byte{0x33}, ticketLen)
	bad := make([]byte, resumeLen)
	copy(bad[segment.ConnNonceLen:], fake)
	if _, err := s.Resume(bad); err != ErrBadTicket {
		t.Fatalf("fake ticket: got %v, want ErrBadTicket", err)
	}
}

func TestVerifyAuthRejects(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(t)
	connNonce := make([]byte, segment.ConnNonceLen)

	hdr, body, _ := c.BuildAuthRequest(connNonce)

	// Wrong PSK on the server side.
	s2, _ := NewServer([]byte("wrong-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	if _, _, err := s2.VerifyAuth(hdr, body); err != ErrBadAuth {
		t.Fatalf("wrong psk: got %v, want ErrBadAuth", err)
	}
	// Tampered body.
	bad := append([]byte(nil), body...)
	bad[len(bad)-1] ^= 0x01
	if _, _, err := s.VerifyAuth(hdr, bad); err != ErrBadAuth {
		t.Fatalf("tampered body: got %v, want ErrBadAuth", err)
	}
	// Tampered header.
	if _, _, err := s.VerifyAuth(hdr+"00", body); err != ErrBadAuth {
		t.Fatalf("tampered header: got %v, want ErrBadAuth", err)
	}
	// Garbage.
	if _, _, err := s.VerifyAuth("not-a-header", body); err != ErrBadAuth {
		t.Fatalf("garbage header: got %v, want ErrBadAuth", err)
	}
}

func TestVerifyAuthStaleTimestamp(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(t)
	// Move the server clock forward beyond the replay window.
	old := s.now
	s.now = func() time.Time { return old().Add(2 * time.Minute) }
	defer func() { s.now = old }()

	hdr, body, _ := c.BuildAuthRequest(make([]byte, segment.ConnNonceLen))
	if _, _, err := s.VerifyAuth(hdr, body); err != ErrStale {
		t.Fatalf("stale ts: got %v, want ErrStale", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s, err := NewServer([]byte("test-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	connNonce := make([]byte, segment.ConnNonceLen)
	hdr, body, _ := c.BuildAuthRequest(connNonce)
	sess, _, err := s.VerifyAuth(hdr, body)
	if err != nil {
		t.Fatal(err)
	}
	sess.Expires = time.Now().Add(-time.Minute) // force expiry
	ticket, _ := s.IssueTicket(sess)
	resp := append(append([]byte(nil), ticket...), sess.Key[:]...)
	cs, _ := SessionFromResponse(resp, time.Hour)
	payload, _ := BuildResumePayload(cs, connNonce)
	if _, err := s.Resume(payload); err != ErrExpired {
		t.Fatalf("expired session: got %v, want ErrExpired", err)
	}
}

func TestSessionTableEviction(t *testing.T) {
	s, err := NewServer([]byte("test-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	// Force the eviction path by temporarily shrinking the limit.
	s.setMaxSessions(2)

	connNonce := make([]byte, segment.ConnNonceLen)
	var sessions []*Session
	for i := 0; i < 5; i++ {
		hdr, body, _ := c.BuildAuthRequest(connNonce)
		sess, _, err := s.VerifyAuth(hdr, body)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, sess)
	}
	if len(s.sessions) > 2 {
		t.Fatalf("session table grew beyond cap: %d", len(s.sessions))
	}
}

func BenchmarkVerifyAuth(b *testing.B) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(b)
	s.setMaxSessions(1000) // keep eviction O(1) for long runs
	connNonce := make([]byte, segment.ConnNonceLen)
	// Fresh request per iteration: the request timestamp must stay in
	// the replay window even for long benchmark runs.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hdr, body, _ := c.BuildAuthRequest(connNonce)
		if _, _, err := s.VerifyAuth(hdr, body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResume(b *testing.B) {
	c, _ := NewClient([]byte("test-psk-0123456789abcdef"))
	s := newTestServer(b)
	s.setMaxSessions(1000)
	nonce := make([]byte, segment.ConnNonceLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs := fullHandshake(b, c, s, nonce)
		payload, _ := BuildResumePayload(cs, nonce)
		if _, err := s.Resume(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// TestBogusResumeFloodDoesNotGrowUsed guards the used-ticket table:
// invalid/unauthenticated resume payloads must be rejected before the
// table is touched, so an unauthenticated flood cannot OOM the server.
func TestBogusResumeFloodDoesNotGrowUsed(t *testing.T) {
	s, err := NewServer([]byte("test-psk-0123456789abcdef"), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Hand-roll a well-formed-length but garbage payload (bogus ticket
	// bytes, bogus HMAC): must be rejected as BadTicket/BadResume
	// without inserting into used.
	bogus := make([]byte, resumeLen)
	for i := range bogus {
		bogus[i] = byte(i * 7)
	}
	before := len(s.used)
	for i := 0; i < 20000; i++ {
		if _, err := s.Resume(bogus); err == nil {
			t.Fatal("bogus resume accepted")
		}
	}
	if grew := len(s.used) - before; grew != 0 {
		t.Fatalf("bogus flood grew used table by %d entries", grew)
	}
}
