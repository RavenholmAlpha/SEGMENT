package segment

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testSession(t *testing.T) (*Session, *Session) {
	t.Helper()
	connNonce := make([]byte, ConnNonceLen)
	rand.Read(connNonce)
	client, err := NewSession(connNonce)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(connNonce)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	if err := client.Establish(key); err != nil {
		t.Fatal(err)
	}
	if err := server.Establish(key); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestEncodeBeforeEstablish(t *testing.T) {
	s, _ := NewSession(make([]byte, ConnNonceLen))
	if _, err := s.Encode(DirClientToServer, 1, FrameData, 0, []byte("x"), 0); err != ErrKeyNotReady {
		t.Fatalf("want ErrKeyNotReady, got %v", err)
	}
	if _, err := s.Decode(DirServerToClient, 1, make([]byte, headerLen+16)); err != ErrKeyNotReady {
		t.Fatalf("want ErrKeyNotReady, got %v", err)
	}
}

func TestDataRoundTripBothDirections(t *testing.T) {
	client, server := testSession(t)
	// Multiple frames on one stream, both directions, interleaved.
	for i := 0; i < 16; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1000+i)
		cf, err := client.Encode(DirClientToServer, 3, FrameData, 0, BuildDataPayload(payload), 0)
		if err != nil {
			t.Fatal(err)
		}
		f, err := server.Decode(DirClientToServer, 3, cf)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type != FrameData || f.Flags != 0 {
			t.Fatalf("bad frame: %v %v", f.Type, f.Flags)
		}
		got, err := ParseDataPayload(f.Payload)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch on frame %d: %v", i, err)
		}

		srvPayload := bytes.Repeat([]byte{0xaa}, 500+i)
		sf, err := server.Encode(DirServerToClient, 3, FrameData, FlagFIN, BuildDataPayload(srvPayload), 0)
		if err != nil {
			t.Fatal(err)
		}
		f2, err := client.Decode(DirServerToClient, 3, sf)
		if err != nil {
			t.Fatal(err)
		}
		if f2.Flags != FlagFIN {
			t.Fatalf("fin flag lost")
		}
		got2, _ := ParseDataPayload(f2.Payload)
		if !bytes.Equal(got2, srvPayload) {
			t.Fatalf("server payload mismatch on frame %d", i)
		}
	}
}

func TestOrderingEnforced(t *testing.T) {
	client, server := testSession(t)
	var frames [][]byte
	for i := 0; i < 3; i++ {
		cf, err := client.Encode(DirClientToServer, 5, FrameData, 0, BuildDataPayload([]byte{byte(i)}), 0)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, cf)
	}
	// Decoding frame 1 before frame 0 must fail (counter mismatch).
	if _, err := server.Decode(DirClientToServer, 5, frames[1]); err == nil {
		t.Fatal("out-of-order decode should fail")
	}
	for i := 0; i < 3; i++ {
		if _, err := server.Decode(DirClientToServer, 5, frames[i]); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
}

func TestPadding(t *testing.T) {
	client, server := testSession(t)
	payload := BuildDataPayload(bytes.Repeat([]byte{0x42}, 100)) // 102 bytes
	cf, err := client.Encode(DirClientToServer, 7, FrameData, 0, payload, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf) != 300 {
		t.Fatalf("padded size = %d, want 300", len(cf))
	}
	f, err := server.Decode(DirClientToServer, 7, cf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDataPayload(f.Payload)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x42}, 100)) {
		t.Fatalf("padded payload corrupted: %v", err)
	}
	// padTo too small for payload + overhead.
	if _, err := client.Encode(DirClientToServer, 7, FrameData, 0, payload, 4); err == nil {
		t.Fatal("expected error for padTo smaller than payload")
	}
	// padTo exceeding the 255-byte padding limit.
	if _, err := client.Encode(DirClientToServer, 7, FrameData, 0, payload, 2048); err == nil {
		t.Fatal("expected error for excessive padTo")
	}
}

func TestTamperRejected(t *testing.T) {
	client, server := testSession(t)
	cf, err := client.Encode(DirClientToServer, 9, FrameData, 0, BuildDataPayload([]byte("secret")), 0)
	if err != nil {
		t.Fatal(err)
	}
	cf[len(cf)-1] ^= 0x01 // flip a ciphertext bit
	if _, err := server.Decode(DirClientToServer, 9, cf); err == nil {
		t.Fatal("tampered frame accepted")
	}
	// Tampering with the header must also fail (header is AAD).
	cf2, _ := client.Encode(DirClientToServer, 9, FrameData, 0, BuildDataPayload([]byte("secret")), 0)
	cf2[0] ^= 0x20
	if _, err := server.Decode(DirClientToServer, 9, cf2); err == nil {
		t.Fatal("header-tampered frame accepted")
	}
}

func TestCrossStreamIsolation(t *testing.T) {
	client, server := testSession(t)
	// Same payload/order on two different streams must not interfere.
	for _, st := range []uint32{11, 12} {
		cf, err := client.Encode(DirClientToServer, st, FrameData, 0, BuildDataPayload([]byte("x")), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Decode(DirClientToServer, st, cf); err != nil {
			t.Fatalf("stream %d: %v", st, err)
		}
	}
	// A frame from stream 11 cannot be decoded as stream 12.
	cf, _ := client.Encode(DirClientToServer, 11, FrameData, 0, BuildDataPayload([]byte("x")), 0)
	if _, err := server.Decode(DirClientToServer, 12, cf); err == nil {
		t.Fatal("cross-stream decode should fail")
	}
}

func TestAuthResumeCleartext(t *testing.T) {
	client, server := testSession(t)
	payload := make([]byte, 100) // resume payload would be 116B
	rand.Read(payload)
	cf, err := client.Encode(DirClientToServer, 1, FrameAuthResume, 0, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf) != authResumePadTo {
		t.Fatalf("resume frame size = %d, want %d", len(cf), authResumePadTo)
	}
	// Must be decodable even before Establish on the server side.
	raw, err := server.Decode(DirClientToServer, 1, cf)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Type != FrameAuthResume || !bytes.Equal(raw.Payload, payload) {
		t.Fatalf("resume payload mismatch")
	}
	// The frame must be readable on the wire (cleartext).
	if !bytes.Equal(cf[headerLen:headerLen+len(payload)], payload) {
		t.Fatal("resume frame is not cleartext")
	}
}

func TestMaxPayload(t *testing.T) {
	client, server := testSession(t)
	// +2 length prefix +16 tag must fit exactly in 65535.
	ok := bytes.Repeat([]byte{0x77}, maxPayloadLen-2)
	cf, err := client.Encode(DirClientToServer, 13, FrameData, 0, BuildDataPayload(ok), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decode(DirClientToServer, 13, cf); err != nil {
		t.Fatal(err)
	}
	tooBig := bytes.Repeat([]byte{0x78}, maxPayloadLen) // +2 prefix +16 tag overflows
	if _, err := client.Encode(DirClientToServer, 13, FrameData, 0, BuildDataPayload(tooBig), 0); err != ErrPayloadTooBig {
		t.Fatalf("overflow not caught: %v", err)
	}
}

func TestResumeHMAC(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	a := ResumeHMAC(key, []byte("nonce"), []byte("fresh"), []byte("ticket"))
	b := ResumeHMAC(key, []byte("nonce"), []byte("fresh"), []byte("ticket"))
	c := ResumeHMAC(key, []byte("nonceX"), []byte("fresh"), []byte("ticket"))
	if !bytes.Equal(a, b) {
		t.Fatal("HMAC not deterministic")
	}
	if bytes.Equal(a, c) {
		t.Fatal("HMAC ignores connNonce")
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	client, server := testSession(&testing.T{})
	payload := BuildDataPayload(bytes.Repeat([]byte{0x5a}, 16384))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cf, err := client.Encode(DirClientToServer, 1, FrameData, 0, payload, 0)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := server.Decode(DirClientToServer, 1, cf); err != nil {
			b.Fatal(err)
		}
	}
}
