// Package segment implements the Segment inner protocol: the frame
// codec, per-session authenticated encryption and padding.
//
// Wire layout of a frame (lengths are big-endian):
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Type | Flags |  PadLen  |             Length                 |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                   Payload (ciphertext)                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The header is 4 bytes; Length is the payload size (ciphertext,
// including the 16-byte GCM tag) for encrypted frames, or the
// plaintext size for the cleartext FrameAuthResume frame.
//
// Segment frames are carried one-per HTTP/2 DATA frame, so a stream ID
// is not needed inside the frame. FrameAuthResume is the only frame
// whose payload travels in cleartext: it carries an opaque ticket and
// an HMAC proving possession of the session key (see internal/auth).
package segment

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameType enumerates Segment frame types.
type FrameType uint8

const (
	FrameOpen       FrameType = 0 // C→S: open a channel (address in payload)
	FrameData       FrameType = 1 // bidirectional: channel data
	FrameClose      FrameType = 2 // bidirectional: close channel
	FrameKeepalive  FrameType = 3 // bidirectional: keepalive (control stream)
	FrameAck        FrameType = 4 // bidirectional: ack of control frames
	FrameAuthResume FrameType = 5 // C→S: 0-RTT resume (cleartext payload)
	frameTypeMax    FrameType = 6
)

func (t FrameType) String() string {
	switch t {
	case FrameOpen:
		return "open"
	case FrameData:
		return "data"
	case FrameClose:
		return "close"
	case FrameKeepalive:
		return "keepalive"
	case FrameAck:
		return "ack"
	case FrameAuthResume:
		return "auth-resume"
	default:
		return fmt.Sprintf("frame(%d)", uint8(t))
	}
}

// Flags are per-frame bit flags.
type Flags uint8

const (
	FlagUDP Flags = 1 << iota // OPEN: channel carries UDP datagrams
	FlagFIN                   // DATA: end of this direction's data
	FlagRST                   // CLOSE: reset (vs graceful)
)

// Protocol constants.
const (
	headerLen       = 4
	tagLen          = 16 // AES-256-GCM tag
	maxCipherLen    = 65535
	maxPayloadLen   = maxCipherLen - tagLen
	MaxPadLen       = 255
	ConnNonceLen    = 16
	FreshNonceLen   = 16
	HmacLen         = 32
	authResumePadTo = 256 // fixed on-wire size for the resume frame
)

// Sentinel errors.
var (
	ErrFrameTooShort = errors.New("segment: frame shorter than header")
	ErrFrameTooLong  = errors.New("segment: frame length mismatch")
	ErrBadPad        = errors.New("segment: padding length out of range")
	ErrBadType       = errors.New("segment: invalid frame type")
	ErrKeyNotReady   = errors.New("segment: session key not established")
	ErrPayloadTooBig = errors.New("segment: payload too large for frame")
	ErrBadOpen       = errors.New("segment: malformed open payload")
	ErrBadData       = errors.New("segment: malformed data payload")
)

// Frame is a decoded Segment frame. Payload is the authenticated
// plaintext with trailing padding removed.
type Frame struct {
	Type    FrameType
	Flags   Flags
	Payload []byte
}

// TagLen returns the AES-256-GCM tag length in bytes.
func TagLen() int { return tagLen }

// putHeader writes the 4-byte frame header.
func putHeader(dst []byte, t FrameType, f Flags, padLen, length int) {
	dst[0] = byte(t)<<5 | byte(f)&0x1f
	dst[1] = byte(padLen)
	binary.BigEndian.PutUint16(dst[2:4], uint16(length))
}

// parseHeader reads and validates the 4-byte frame header.
func parseHeader(b []byte) (t FrameType, f Flags, padLen, length int, err error) {
	if len(b) < headerLen {
		return 0, 0, 0, 0, ErrFrameTooShort
	}
	t = FrameType(b[0] >> 5)
	f = Flags(b[0] & 0x1f)
	padLen = int(b[1])
	length = int(binary.BigEndian.Uint16(b[2:4]))
	if t >= frameTypeMax {
		return 0, 0, 0, 0, ErrBadType
	}
	return t, f, padLen, length, nil
}

// BuildOpenPayload builds a FRAME_OPEN payload: addrLen(1) || addr || port(2).
func BuildOpenPayload(addr string, port uint16) []byte {
	b := make([]byte, 1+len(addr)+2)
	b[0] = byte(len(addr))
	copy(b[1:], addr)
	binary.BigEndian.PutUint16(b[1+len(addr):], port)
	return b
}

// ParseOpenPayload extracts the target address and port of a FRAME_OPEN.
func ParseOpenPayload(p []byte) (addr string, port uint16, err error) {
	if len(p) < 3 {
		return "", 0, ErrBadOpen
	}
	n := int(p[0])
	if 1+n+2 > len(p) {
		return "", 0, ErrBadOpen
	}
	return string(p[1 : 1+n]), binary.BigEndian.Uint16(p[1+n:]), nil
}

// BuildDataPayload builds a FRAME_DATA payload: dataLen(2) || data.
// For UDP channels each FRAME_DATA carries exactly one datagram.
func BuildDataPayload(data []byte) []byte {
	b := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(b, uint16(len(data)))
	copy(b[2:], data)
	return b
}

// ParseDataPayload extracts the data bytes of a FRAME_DATA payload.
func ParseDataPayload(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, ErrBadData
	}
	n := int(binary.BigEndian.Uint16(p))
	if 2+n > len(p) {
		return nil, ErrBadData
	}
	return p[2 : 2+n], nil
}

// BuildClosePayload builds a FRAME_CLOSE payload: reason(1).
func BuildClosePayload(reason byte) []byte { return []byte{reason} }

// ParseClosePayload extracts the close reason.
func ParseClosePayload(p []byte) byte {
	if len(p) == 0 {
		return 0
	}
	return p[0]
}

// BuildKeepalivePayload builds a FRAME_KEEPALIVE payload: ts(8, BE).
func BuildKeepalivePayload(ts uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, ts)
	return b
}

// ParseKeepalivePayload extracts the keepalive timestamp.
func ParseKeepalivePayload(p []byte) (uint64, error) {
	if len(p) < 8 {
		return 0, ErrBadData
	}
	return binary.BigEndian.Uint64(p), nil
}

// BuildAckPayload builds a FRAME_ACK payload: echo(8, BE).
func BuildAckPayload(echo uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, echo)
	return b
}

// ParseAckPayload extracts the echoed value.
func ParseAckPayload(p []byte) (uint64, error) {
	return ParseKeepalivePayload(p)
}
