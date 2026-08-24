package segment

import (
	"bytes"
	"testing"
)

func TestParseHeaderErrors(t *testing.T) {
	if _, _, _, _, err := parseHeader(nil); err != ErrFrameTooShort {
		t.Fatalf("short frame: got %v", err)
	}
	// Bad type.
	b := []byte{byte(frameTypeMax) << 5, 0, 0, 1}
	if _, _, _, _, err := parseHeader(b); err != ErrBadType {
		t.Fatalf("bad type: got %v", err)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	var b [headerLen]byte
	putHeader(b[:], FrameData, FlagFIN, 42, 12345)
	typ, fl, pad, length, err := parseHeader(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameData || fl != FlagFIN || pad != 42 || length != 12345 {
		t.Fatalf("round trip mismatch: %v %v %d %d", typ, fl, pad, length)
	}
}

func TestOpenPayload(t *testing.T) {
	p := BuildOpenPayload("203.0.113.7", 443)
	addr, port, err := ParseOpenPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "203.0.113.7" || port != 443 {
		t.Fatalf("got %q %d", addr, port)
	}
	for _, bad := range [][]byte{nil, {0, 1}, {3, 'a', 'b', 0, 1}} {
		if _, _, err := ParseOpenPayload(bad); err != ErrBadOpen {
			t.Fatalf("malformed open %v: got %v", bad, err)
		}
	}
}

func TestDataPayload(t *testing.T) {
	d := []byte("hello segment")
	p := BuildDataPayload(d)
	got, err := ParseDataPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, d) {
		t.Fatalf("data mismatch: %q", got)
	}
	if _, err := ParseDataPayload([]byte{0, 5, 'a'}); err != ErrBadData {
		t.Fatalf("malformed data: got %v", err)
	}
}

func TestKeepaliveAckClose(t *testing.T) {
	ts, _ := ParseKeepalivePayload(BuildKeepalivePayload(0x0102030405060708))
	if ts != 0x0102030405060708 {
		t.Fatalf("ts mismatch: %x", ts)
	}
	echo, _ := ParseAckPayload(BuildAckPayload(42))
	if echo != 42 {
		t.Fatalf("echo mismatch: %d", echo)
	}
	if got := ParseClosePayload(BuildClosePayload(7)); got != 7 {
		t.Fatalf("reason mismatch: %d", got)
	}
}
