package segment

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const keyLen = 32

// DeriveKey derives a 32-byte key from secret and an info label
// (HKDF-SHA256 with an empty salt). Used for keyAuth, keySrv and the
// per-connection data key.
func DeriveKey(secret []byte, info string) ([]byte, error) {
	return hkdfExpand(secret, info, keyLen)
}

func hkdfExpand(secret []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, n)
}

// ResumeHMAC returns the proof that the caller knows sessionKey:
// HMAC-SHA256(sessionKey, connNonce || freshNonce || ticket).
func ResumeHMAC(sessionKey, connNonce, freshNonce, ticket []byte) []byte {
	m := hmac.New(sha256.New, sessionKey)
	m.Write(connNonce)
	m.Write(freshNonce)
	m.Write(ticket)
	return m.Sum(nil)
}

// Direction selects which side of the connection is sending: client→
// server or server→client. Each direction derives its own per-stream
// keys, so both may use an independent counter nonce.
type Direction bool

const (
	DirClientToServer Direction = false
	DirServerToClient Direction = true
)

func (d Direction) byte() byte {
	if d == DirServerToClient {
		return 1
	}
	return 0
}

// Session encrypts and decrypts Segment frames for one connection.
//
// A fresh connNonce (16 random bytes chosen by the client) is mixed
// into the data key so every connection derives a distinct key,
// providing forward secrecy between connections even when a session
// ticket is reused. Each stream gets its own key per direction
// (HKDF(keyData, streamID || dir)), which makes a plain counter nonce
// safe: GCM nonces are unique per (key, counter).
type Session struct {
	mu        sync.RWMutex
	connNonce [ConnNonceLen]byte
	keyData   []byte // nil until Establish
	client    *streamDir
	server    *streamDir
}

// NewSession creates a session bound to a fresh connNonce. The session
// is not usable for encrypted frames until Establish is called.
func NewSession(connNonce []byte) (*Session, error) {
	if len(connNonce) != ConnNonceLen {
		return nil, errors.New("segment: bad connNonce length")
	}
	s := &Session{
		client: newStreamDir(DirClientToServer),
		server: newStreamDir(DirServerToClient),
	}
	copy(s.connNonce[:], connNonce)
	return s, nil
}

// ConnNonce returns the connection nonce.
func (s *Session) ConnNonce() []byte { return s.connNonce[:] }

// Established reports whether the session key has been set.
func (s *Session) Established() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyData != nil
}

// Establish derives the per-connection data key from sessionKey and
// unlocks frame crypto. Both sides must call it with the same
// sessionKey and connNonce.
func (s *Session) Establish(sessionKey []byte) error {
	kd, err := DeriveKey(sessionKey, "segment-data")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyData = kd
	s.client.keyData = kd
	s.server.keyData = kd
	return nil
}

// ErrDstTooSmall is returned by EncodeAt when the provided buffer
// cannot hold the frame.
var ErrDstTooSmall = errors.New("segment: encode destination too small")

// Encode builds one frame (header + ciphertext) into a fresh buffer.
// See EncodeAt for the zero-allocation variant.
func (s *Session) Encode(dir Direction, st uint32, t FrameType, f Flags, payload []byte, padTo int) ([]byte, error) {
	if t == FrameAuthResume {
		return encodeClear(t, f, payload, padTo)
	}
	if len(payload)+tagLen > maxCipherLen {
		return nil, ErrPayloadTooBig
	}
	s.mu.RLock()
	kd := s.keyData
	d := s.dir(dir)
	s.mu.RUnlock()
	if kd == nil {
		return nil, ErrKeyNotReady
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	gcm, nonce, err := d.cipher(st)
	if err != nil {
		return nil, err
	}
	padLen := 0
	plain := payload
	if padTo > 0 {
		padLen = padTo - headerLen - tagLen - len(payload)
		if padLen < 0 {
			return nil, fmt.Errorf("segment: payload %d too large for padTo %d", len(payload), padTo)
		}
		if padLen > MaxPadLen {
			return nil, fmt.Errorf("segment: padTo %d exceeds max padding", padTo)
		}
		plain = make([]byte, len(payload)+padLen)
		copy(plain, payload)
		if _, err := rand.Read(plain[len(payload):]); err != nil {
			return nil, err
		}
	}
	out := make([]byte, headerLen+tagLen+len(plain))
	putHeader(out, t, f, padLen, tagLen+len(plain))
	gcm.Seal(out[headerLen:headerLen], nonce[:], plain, out[:headerLen])
	incNonce(nonce)
	return out, nil
}

// EncodeAt is Encode into a caller-provided buffer dst with enough
// capacity (a sync.Pool buffer in the hot path). The returned slice is
// dst[:n]; the caller must not retain it beyond the frame's write. This
// removes all per-frame allocations on the send path: the padded
// plaintext, when any, is assembled in place in dst and GCM seals
// in-place (cipher.AEAD.Seal allows dst/plain overlap).
func (s *Session) EncodeAt(dir Direction, st uint32, t FrameType, f Flags, payload []byte, padTo int, dst []byte) ([]byte, error) {
	if t == FrameAuthResume {
		return encodeClearAt(t, f, payload, padTo, dst)
	}
	if len(payload)+tagLen > maxCipherLen {
		return nil, ErrPayloadTooBig
	}
	s.mu.RLock()
	kd := s.keyData
	d := s.dir(dir)
	s.mu.RUnlock()
	if kd == nil {
		return nil, ErrKeyNotReady
	}
	padLen := 0
	if padTo > 0 {
		padLen = padTo - headerLen - tagLen - len(payload)
		if padLen < 0 {
			return nil, fmt.Errorf("segment: payload %d too large for padTo %d", len(payload), padTo)
		}
		if padLen > MaxPadLen {
			return nil, fmt.Errorf("segment: padTo %d exceeds max padding", padTo)
		}
	}
	need := headerLen + tagLen + len(payload) + padLen
	if need > len(dst) {
		return nil, ErrDstTooSmall
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	gcm, nonce, err := d.cipher(st)
	if err != nil {
		return nil, err
	}
	// In-place padded plaintext lives in dst right after the header.
	if padLen > 0 {
		pl := dst[headerLen : headerLen+len(payload)+padLen]
		copy(pl, payload)
		if _, err := rand.Read(pl[len(payload):]); err != nil {
			return nil, err
		}
		putHeader(dst, t, f, padLen, tagLen+len(pl))
		gcm.Seal(dst[headerLen:headerLen], nonce[:], pl, dst[:headerLen])
		incNonce(nonce)
		return dst[:headerLen+tagLen+len(pl)], nil
	}
	putHeader(dst, t, f, 0, tagLen+len(payload))
	gcm.Seal(dst[headerLen:headerLen], nonce[:], payload, dst[:headerLen])
	incNonce(nonce)
	return dst[:headerLen+tagLen+len(payload)], nil
}

// encodeClearAt is encodeClear into a caller-provided buffer.
func encodeClearAt(t FrameType, f Flags, payload []byte, padTo int, dst []byte) ([]byte, error) {
	if padTo == 0 {
		padTo = authResumePadTo
	}
	padLen := padTo - headerLen - len(payload)
	if padLen < 0 {
		return nil, fmt.Errorf("segment: resume payload too large for padTo %d", padTo)
	}
	if padLen > MaxPadLen {
		return nil, fmt.Errorf("segment: padTo %d exceeds max padding", padTo)
	}
	need := headerLen + len(payload) + padLen
	if need > len(dst) {
		return nil, ErrDstTooSmall
	}
	buf := dst[:need]
	putHeader(buf, t, f, padLen, len(payload)+padLen)
	copy(buf[headerLen:], payload)
	if _, err := rand.Read(buf[headerLen+len(payload):]); err != nil {
		return nil, err
	}
	return buf, nil
}

// Decode parses and authenticates one frame. dir must be the direction
// of the sender. Frames must be decoded in the order they were
// encoded: the implicit counter nonce advances per frame.
func (s *Session) Decode(dir Direction, st uint32, frame []byte) (Frame, error) {
	t, f, padLen, length, err := parseHeader(frame)
	if err != nil {
		return Frame{}, err
	}
	if t == FrameAuthResume {
		if length > len(frame)-headerLen {
			return Frame{}, ErrFrameTooLong
		}
		pl := frame[headerLen : headerLen+length]
		if padLen > len(pl) {
			return Frame{}, ErrBadPad
		}
		return Frame{Type: t, Flags: f, Payload: pl[:len(pl)-padLen]}, nil
	}
	s.mu.RLock()
	kd := s.keyData
	d := s.dir(dir)
	s.mu.RUnlock()
	if kd == nil {
		return Frame{}, ErrKeyNotReady
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	gcm, nonce, err := d.cipher(st)
	if err != nil {
		return Frame{}, err
	}
	if length < tagLen || length > len(frame)-headerLen {
		return Frame{}, ErrFrameTooLong
	}
	ct := frame[headerLen : headerLen+length]
	plain, err := gcm.Open(nil, nonce[:], ct, frame[:headerLen])
	if err != nil {
		return Frame{}, err
	}
	incNonce(nonce)
	if padLen > len(plain) {
		return Frame{}, ErrBadPad
	}
	return Frame{Type: t, Flags: f, Payload: plain[:len(plain)-padLen]}, nil
}

func (s *Session) dir(dir Direction) *streamDir {
	if dir == DirServerToClient {
		return s.server
	}
	return s.client
}

// encodeClear builds the cleartext FRAME_AUTH_RESUME frame.
func encodeClear(t FrameType, f Flags, payload []byte, padTo int) ([]byte, error) {
	if padTo == 0 {
		padTo = authResumePadTo
	}
	padLen := padTo - headerLen - len(payload)
	if padLen < 0 {
		return nil, fmt.Errorf("segment: resume payload too large for padTo %d", padTo)
	}
	if padLen > MaxPadLen {
		return nil, fmt.Errorf("segment: padTo %d exceeds max padding", padTo)
	}
	buf := make([]byte, headerLen+len(payload)+padLen)
	putHeader(buf, t, f, padLen, len(payload)+padLen)
	copy(buf[headerLen:], payload)
	if _, err := rand.Read(buf[headerLen+len(payload):]); err != nil {
		return nil, err
	}
	return buf, nil
}

// streamDir holds per-stream ciphers for one direction of the
// connection. Every stream gets its own key derived from keyData with
// the stream ID and direction byte, so the counter nonce is unique per
// (key, counter).
type streamDir struct {
	mu      sync.Mutex
	dir     Direction
	keyData []byte
	m       map[uint32]*streamCipher
}

func newStreamDir(dir Direction) *streamDir {
	return &streamDir{dir: dir, m: make(map[uint32]*streamCipher)}
}

type streamCipher struct {
	gcm   cipher.AEAD
	nonce [12]byte
}

func (d *streamDir) cipher(st uint32) (cipher.AEAD, *[12]byte, error) {
	c, ok := d.m[st]
	if !ok {
		k, err := hkdfExpand(d.keyData, streamInfo(st, d.dir.byte()), keyLen)
		if err != nil {
			return nil, nil, err
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}
		c = &streamCipher{gcm: gcm}
		d.m[st] = c
	}
	return c.gcm, &c.nonce, nil
}

// streamInfo is the HKDF info string for a stream key:
// streamID(4) || dir(1).
func streamInfo(st uint32, dir byte) string {
	var b [5]byte
	binary.BigEndian.PutUint32(b[:4], st)
	b[4] = dir
	return string(b[:])
}

// incNonce advances the 8-byte big-endian counter that occupies the
// first 8 bytes of the 12-byte nonce. The remaining 4 bytes stay zero.
func incNonce(nonce *[12]byte) {
	for i := 7; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
	// Counter exhausted after 2^64 frames in one direction of one
	// stream; practically unreachable.
	panic("segment: stream nonce counter exhausted")
}
