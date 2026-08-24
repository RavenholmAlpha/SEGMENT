package tunnel

import (
	"net"
	"testing"
	"time"

	"segment/internal/auth"
	"segment/internal/h2x"
	"segment/internal/segment"
)

const tunnelTestPSK = "tunnel-test-psk-0123456789abcdef"

// testPair wires a real h2 server (production HandleStream dispatch)
// against a tunnel client over net.Pipe, bypassing TLS.
func testPair(t *testing.T, as *auth.Server) (*Client, *h2x.Conn) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	type sres struct {
		c   *h2x.Conn
		err error
	}
	doneCh := make(chan sres, 1)
	go func() {
		c, err := h2x.ServerConn(serverSide, h2x.DefaultConfig(), func(c *h2x.Conn, st *h2x.Stream) {
			cs := StateFor(c, as, net.Dial, Pacing{})
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
	cc, err := Dial(clientSide, h2x.DefaultConfig(), ac, nil, "video.example.com")
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
