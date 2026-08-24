package tunnel

import (
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"segment/internal/auth"
	"segment/internal/h2x"
	"segment/internal/segment"
)

const tunnelTestPSK = "tunnel-test-psk-0123456789abcdef"

// testPair wires a real h2 server (production HandleStream dispatch)
// against a tunnel client over net.Pipe, bypassing TLS.
func testPair(t *testing.T, as *auth.Server) (*Client, *h2x.Conn) {
	return testPairWithCredential(t, as, nil, nil)
}

// testPairWithCredential wires the real client/server stream admission flow
// over net.Pipe, optionally observing every client-opened stream and starting
// the client with a cached resumable credential.
func testPairWithCredential(t *testing.T, as *auth.Server, cred *auth.ClientSession, observe func(*h2x.Stream)) (*Client, *h2x.Conn) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	type sres struct {
		c   *h2x.Conn
		err error
	}
	doneCh := make(chan sres, 1)
	go func() {
		c, err := h2x.ServerConn(serverSide, h2x.DefaultConfig(), func(c *h2x.Conn, st *h2x.Stream) {
			if observe != nil {
				observe(st)
			}
			cs := StateFor(c, as, net.Dial, Pacing{}, nil)
			if err := cs.HandleStream(st); err == ErrFakeSite {
				// fake-site branch not exercised here
			}
		})
		doneCh <- sres{c, err}
	}()
	ac, err := auth.NewClient([]byte(tunnelTestPSK))
	if err != nil {
		t.Fatal(err)
	}
	cc, err := Dial(clientSide, h2x.DefaultConfig(), ac, cred, "video.example.com")
	if err != nil {
		t.Fatal(err)
	}
	r := <-doneCh
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = cc.Close(); r.c.GoAway() })
	return cc, r.c
}

// TestFullHandshakeControlKeepalive guards M4: a full-handshake
// client's control stream sends *encrypted* keepalives under the
// session key established by the auth POST. The server must decode them
// against the established session and reply FRAME_ACK — not RST the
// stream because the no-key "clear" decoder cannot read them.
func TestFullHandshakeControlKeepalive(t *testing.T) {
	as, err := auth.NewServer([]byte(tunnelTestPSK), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := testPair(t, as)
	if err := cc.Establish(); err != nil {
		t.Fatal(err)
	}

	const ts = 123456789
	p := segment.BuildKeepalivePayload(uint64(ts))
	frame, err := cc.sess.Encode(segment.DirClientToServer, cc.control.ID(), segment.FrameKeepalive, 0, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.control.WriteChunk(frame, false); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		data, end, err := cc.control.ReadData()
		if err != nil {
			t.Fatalf("control stream died instead of ACKing: %v", err)
		}
		f, err := cc.sess.Decode(segment.DirServerToClient, cc.control.ID(), data)
		if err != nil {
			t.Fatalf("decode ACK: %v", err)
		}
		if f.Type == segment.FrameAck {
			got, err := segment.ParseAckPayload(f.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if got != ts {
				t.Fatalf("ACK echo mismatch: got %d want %d", got, ts)
			}
			if status := headerValue(cc.control.Headers(), ":status"); status != "200" {
				t.Fatalf("control status before ACK DATA = %q, want 200", status)
			}
			if contentType := headerValue(cc.control.Headers(), "content-type"); contentType != "video/mp4" {
				t.Fatalf("control content type before ACK DATA = %q, want video/mp4", contentType)
			}
			return
		}
		if end {
			t.Fatal("control stream ended before ACK")
		}
		if time.Now().After(deadline) {
			t.Fatal("no ACK within 5s")
		}
	}
}

// TestTicketResumeUsesAuthenticationPost makes the outer resume admission
// observable: a cached ticket must be proven through the normal auth POST,
// not by a bare media-marked stream. The auth server's Resume path remains
// responsible for consuming the ticket exactly once (also covered end to end).
func TestTicketResumeUsesAuthenticationPost(t *testing.T) {
	as, err := auth.NewServer([]byte(tunnelTestPSK), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := testPair(t, as)
	if err := first.Establish(); err != nil {
		t.Fatal(err)
	}
	cred := first.ClientSession()
	if cred == nil {
		t.Fatal("full handshake did not produce a ticket")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	seen := make(chan []hpack.HeaderField, 1)
	resumed, _ := testPairWithCredential(t, as, cred, func(st *h2x.Stream) {
		select {
		case seen <- append([]hpack.HeaderField(nil), st.Headers()...):
		default:
		}
	})
	defer resumed.Close()

	select {
	case hdrs := <-seen:
		if method := headerValue(hdrs, ":method"); method != "POST" {
			t.Fatalf("resume admission method = %q, want POST", method)
		}
		if path := headerValue(hdrs, ":path"); path != "/api/v1/telemetry" {
			t.Fatalf("resume admission path = %q, want /api/v1/telemetry", path)
		}
		if hasTunnelMarkers(hdrs) {
			t.Fatal("resume admission must not carry media tunnel markers")
		}
	case <-time.After(time.Second):
		t.Fatal("resume admission stream was not opened")
	}
	if err := resumed.WaitReady(time.Second); err != nil {
		t.Fatalf("ticket resume failed: %v", err)
	}
}

// TestTunnelWritesResponseHeadersBeforeData guards the public HTTP/2
// contract of an authenticated media stream. A real media response starts
// with response headers; sending tunnel DATA first makes the tunnel easy to
// distinguish and violates HTTP/2 response semantics.
func TestTunnelWritesResponseHeadersBeforeData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("media payload"))
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	as, err := auth.NewServer([]byte(tunnelTestPSK), time.Hour, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := testPair(t, as)
	if err := cc.Establish(); err != nil {
		t.Fatal(err)
	}

	st, err := cc.h2c.NewStream(cc.tunnelHeaders("/videos/alpha/seg-0.m4s"), false)
	if err != nil {
		t.Fatal(err)
	}
	codec := NewCodec(st, cc.sess, segment.DirClientToServer, segment.DirServerToClient)
	if err := codec.WriteFrame(segment.FrameOpen, 0, segment.BuildOpenPayload(host, uint16(port)), 0); err != nil {
		t.Fatal(err)
	}
	frame, err := codec.ReadFrame()
	if err != nil {
		t.Fatalf("read first tunnel frame: %v", err)
	}
	if frame.Type != segment.FrameData {
		t.Fatalf("first tunnel frame type = %d, want FRAME_DATA", frame.Type)
	}
	if status := headerValue(st.Headers(), ":status"); status != "200" {
		t.Fatalf("status before first DATA = %q, want 200", status)
	}
	if contentType := headerValue(st.Headers(), "content-type"); contentType != "video/mp4" {
		t.Fatalf("content type before first DATA = %q, want video/mp4", contentType)
	}
}
