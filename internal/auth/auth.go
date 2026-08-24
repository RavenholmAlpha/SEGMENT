// Package auth implements Segment authentication: the PSK full
// handshake (an auth blob carried by a normal-looking HTTP POST), the
// server-issued single-use session ticket, and the ticket resume path.
//
// Key material:
//
//	keyAuth  = HKDF(psk, "segment-auth")  — authenticates the handshake
//	keySrv   = random per server process   — encrypts tickets
//	sessionKey = random per session        — inner data key (via HKDF
//	                                          with the per-connection
//	                                          connNonce); handed to the
//	                                          client inside TLS at full
//	                                          handshake time
//
// The ticket is opaque to the client (encrypted with keySrv) and
// contains only sessionID + expiry — never the session key. The client
// caches {ticket, sessionKey} locally and proves knowledge of the key
// at resume time with an HMAC before the client opens its first
// media-marked tunnel stream.
package auth

import (
	"container/heap"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"segment/internal/segment"
)

const (
	authInfo       = "segment-auth"
	sessionIDLen   = 16
	sessionKeyLen  = 32
	ticketNonceLen = 12
	cleanupEvery   = time.Minute
)

// ticketLen and resumeLen depend on segment.TagLen() (a function call),
// so they are vars rather than consts.
const defaultMaxSessions = 100_000

// maxUsedTickets caps the recorded-single-use-ticket table. It only
// ever holds *valid* resumed tickets (see Resume: invalid payloads are
// rejected before insertion), so the bound is a defense-in-depth floor
// against an authorized peer churning resumes.
const maxUsedTickets = 1 << 16

var (
	ticketLen = ticketNonceLen + sessionIDLen + 8 + segment.TagLen() // 52: nonce||id||exp||tag
	resumeLen = segment.ConnNonceLen + ticketLen + segment.FreshNonceLen + segment.HmacLen
)

// Sentinel errors.
var (
	ErrStale          = errors.New("auth: timestamp out of window")
	ErrBadAuth        = errors.New("auth: bad auth request")
	ErrReplay         = errors.New("auth: ticket replay")
	ErrTooManyResumes = errors.New("auth: too many outstanding resumptions")
	ErrBadTicket      = errors.New("auth: bad ticket")
	ErrExpired        = errors.New("auth: ticket expired")
	ErrUnknownSession = errors.New("auth: unknown session")
	ErrBadResume      = errors.New("auth: bad resume proof")
)

// Client holds the PSK and builds full-handshake auth requests.
type Client struct {
	keyAuth []byte
	now     func() time.Time
}

// NewClient derives the client-side key material from the PSK.
func NewClient(psk []byte) (*Client, error) {
	ka, err := segment.DeriveKey(psk, authInfo)
	if err != nil {
		return nil, err
	}
	return &Client{keyAuth: ka, now: time.Now}, nil
}

// BuildAuthRequest produces the header value (ts.hex(hmac)) and body
// (nonce || AES-GCM(keyAuth, ts || clientNonce || connNonce)) for the
// full handshake POST. connNonce is the fresh per-connection nonce the
// client will use for its Segment session.
func (c *Client) BuildAuthRequest(connNonce []byte) (header string, body []byte, err error) {
	if len(connNonce) != segment.ConnNonceLen {
		return "", nil, errors.New("auth: bad connNonce length")
	}
	ts := c.now().UnixMilli()
	clientNonce := make([]byte, segment.FreshNonceLen)
	if _, err := rand.Read(clientNonce); err != nil {
		return "", nil, err
	}
	plain := make([]byte, 8+segment.FreshNonceLen+segment.ConnNonceLen)
	binary.BigEndian.PutUint64(plain, uint64(ts))
	copy(plain[8:], clientNonce)
	copy(plain[8+segment.FreshNonceLen:], connNonce)

	nonce := make([]byte, ticketNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	gcm, err := newGCM(c.keyAuth)
	if err != nil {
		return "", nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	body = append(nonce, ct...)

	m := hmac.New(sha256.New, c.keyAuth)
	m.Write(plain)
	header = fmt.Sprintf("%d.%x", ts, m.Sum(nil))
	return header, body, nil
}

// ClientSession is the cached credential enabling ticket resume.
type ClientSession struct {
	Ticket  []byte // opaque to the client
	Key     [sessionKeyLen]byte
	Expires time.Time
}

// SessionFromResponse parses the full-handshake response body
// (ticket || sessionKey) into a resumable client session.
func SessionFromResponse(body []byte, ttl time.Duration) (*ClientSession, error) {
	if len(body) != ticketLen+sessionKeyLen {
		return nil, ErrBadAuth
	}
	cs := &ClientSession{
		Ticket:  append([]byte(nil), body[:ticketLen]...),
		Expires: time.Now().Add(ttl),
	}
	copy(cs.Key[:], body[ticketLen:])
	return cs, nil
}

// Valid reports whether the cached session is still within its local
// lifetime (the server enforces the authoritative expiry).
func (cs *ClientSession) Valid(now time.Time) bool {
	return now.Before(cs.Expires)
}

// BuildResumePayload builds the ticket-resume POST body:
// connNonce(16) || ticket(52) || freshNonce(16) || hmac(32).
func BuildResumePayload(cs *ClientSession, connNonce []byte) ([]byte, error) {
	fresh := make([]byte, segment.FreshNonceLen)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	p := make([]byte, resumeLen)
	copy(p, connNonce)
	copy(p[segment.ConnNonceLen:], cs.Ticket)
	copy(p[segment.ConnNonceLen+ticketLen:], fresh)
	hm := segment.ResumeHMAC(cs.Key[:], connNonce, fresh, cs.Ticket)
	copy(p[segment.ConnNonceLen+ticketLen+segment.FreshNonceLen:], hm)
	return p, nil
}

// Server validates auth requests and issues/resumes sessions.
type Server struct {
	keyAuth      []byte
	keySrv       []byte
	ticketTTL    time.Duration
	replayWindow time.Duration
	now          func() time.Time

	// maxSessions caps the live session table (guarded by mu; set via
	// setMaxSessions, shrunken in tests to exercise eviction).
	maxSessions int

	mu        sync.Mutex
	sessions  map[[sessionIDLen]byte]*Session
	used      map[[32]byte]time.Time // sha256(ticket) -> expiry; single-use
	expHeap   sessionHeap            // min-heap by expiry for O(log n) eviction
	lastClean time.Time
}

// Session is a server-side authenticated session.
type Session struct {
	ID      [sessionIDLen]byte
	Key     [sessionKeyLen]byte
	Expires time.Time
}

// NewServer builds a server auth engine. psk is the shared pre-shared
// key; keySrv may be nil to derive a fresh random ticket key (tickets
// die on restart, which is safe: clients fall back to full auth).
func NewServer(psk []byte, ticketTTL, replayWindow time.Duration, keySrv []byte) (*Server, error) {
	ka, err := segment.DeriveKey(psk, authInfo)
	if err != nil {
		return nil, err
	}
	if len(keySrv) != 0 && len(keySrv) != sessionKeyLen {
		return nil, errors.New("auth: bad keySrv length")
	}
	if len(keySrv) == 0 {
		keySrv = make([]byte, sessionKeyLen)
		if _, err := rand.Read(keySrv); err != nil {
			return nil, err
		}
	}
	if ticketTTL <= 0 {
		ticketTTL = 24 * time.Hour
	}
	if replayWindow <= 0 {
		replayWindow = 30 * time.Second
	}
	return &Server{
		keyAuth:      ka,
		keySrv:       keySrv,
		ticketTTL:    ticketTTL,
		replayWindow: replayWindow,
		now:          time.Now,
		maxSessions:  defaultMaxSessions,
		sessions:     make(map[[sessionIDLen]byte]*Session),
		used:         make(map[[32]byte]time.Time),
		lastClean:    time.Now(),
	}, nil
}

// setMaxSessions shrinks the session-table cap (tests only).
func (s *Server) setMaxSessions(n int) {
	s.mu.Lock()
	s.maxSessions = n
	s.mu.Unlock()
}

// sessionHeap is a min-heap of sessions ordered by expiry.
type sessionHeap []sessionItem

type sessionItem struct {
	exp time.Time
	id  [sessionIDLen]byte
}

func (h sessionHeap) Len() int           { return len(h) }
func (h sessionHeap) Less(i, j int) bool { return h[i].exp.Before(h[j].exp) }
func (h sessionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *sessionHeap) Push(x any) { *h = append(*h, x.(sessionItem)) }
func (h *sessionHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

func (h *sessionHeap) top() (sessionItem, bool) {
	if len(*h) == 0 {
		return sessionItem{}, false
	}
	return (*h)[0], true
}

// VerifyAuth validates a full-handshake request and returns the new
// session together with the client's fresh per-connection nonce (mixed
// into the connection's data key). The caller issues the ticket with
// IssueTicket.
func (s *Server) VerifyAuth(header string, body []byte) (*Session, []byte, error) {
	ts, macHex, err := parseAuthHeader(header)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	if ts < now.Add(-s.replayWindow).UnixMilli() || ts > now.Add(s.replayWindow).UnixMilli() {
		return nil, nil, ErrStale
	}
	if len(body) < ticketNonceLen+segment.TagLen() {
		return nil, nil, ErrBadAuth
	}
	nonce, ct := body[:ticketNonceLen], body[ticketNonceLen:]
	gcm, err := newGCM(s.keyAuth)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, nil, ErrBadAuth
	}
	if len(plain) != 8+segment.FreshNonceLen+segment.ConnNonceLen {
		return nil, nil, ErrBadAuth
	}
	if int64(binary.BigEndian.Uint64(plain)) != ts {
		return nil, nil, ErrBadAuth
	}
	want := hmacSHA256(s.keyAuth, plain)
	if subtle.ConstantTimeCompare(want, macHex) != 1 {
		return nil, nil, ErrBadAuth
	}
	connNonce := plain[8+segment.FreshNonceLen:]

	sess := &Session{Expires: now.Add(s.ticketTTL)}
	if _, err := rand.Read(sess.ID[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(sess.Key[:]); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	s.cleanupLocked(now)
	if len(s.sessions) >= s.maxSessions {
		s.evictLocked()
	}
	s.sessions[sess.ID] = sess
	heap.Push(&s.expHeap, sessionItem{exp: sess.Expires, id: sess.ID})
	s.mu.Unlock()
	return sess, connNonce, nil
}

// IssueTicket wraps a session in an opaque ticket:
// nonce(12) || AES-GCM(keySrv, id(16) || exp(8)).
func (s *Server) IssueTicket(sess *Session) ([]byte, error) {
	plain := make([]byte, sessionIDLen+8)
	copy(plain, sess.ID[:])
	binary.BigEndian.PutUint64(plain[sessionIDLen:], uint64(sess.Expires.UnixMilli()))
	nonce := make([]byte, ticketNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(s.keySrv)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, ct...), nil
}

// Resume validates the ticket-resume POST payload and returns the session
// key. The ticket is single-use: a replayed resume payload is rejected.
// Invalid payloads (garbage, forged, expired) are rejected *before* the
// used table is touched, so an unauthenticated flood of bogus resumes
// cannot grow memory (the used table only records valid tickets).
func (s *Server) Resume(payload []byte) (*Session, error) {
	if len(payload) != resumeLen {
		return nil, ErrBadResume
	}
	connNonce := payload[:segment.ConnNonceLen]
	ticket := payload[segment.ConnNonceLen : segment.ConnNonceLen+ticketLen]
	fresh := payload[segment.ConnNonceLen+ticketLen : segment.ConnNonceLen+ticketLen+segment.FreshNonceLen]
	got := payload[segment.ConnNonceLen+ticketLen+segment.FreshNonceLen:]

	// 1. Decrypt and validate the ticket itself.
	nonce, ct := ticket[:ticketNonceLen], ticket[ticketNonceLen:]
	gcm, err := newGCM(s.keySrv)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrBadTicket
	}
	now := s.now()
	var id [sessionIDLen]byte
	copy(id[:], plain[:sessionIDLen])
	exp := int64(binary.BigEndian.Uint64(plain[sessionIDLen:]))
	if exp < now.UnixMilli() {
		return nil, ErrExpired
	}

	// 2. Resolve the session and verify the fresh-nonce proof.
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		return nil, ErrUnknownSession
	}
	want := segment.ResumeHMAC(sess.Key[:], connNonce, fresh, ticket)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, ErrBadResume
	}

	// 3. Mark the ticket single-use. The check-and-set is atomic under
	// s.mu, so concurrent replays of the same ticket lose deterministically.
	tkh := sha256.Sum256(ticket)
	s.mu.Lock()
	s.cleanupLocked(now)
	if _, dup := s.used[tkh]; dup {
		s.mu.Unlock()
		return nil, ErrReplay
	}
	if len(s.used) >= maxUsedTickets {
		s.mu.Unlock()
		return nil, ErrTooManyResumes
	}
	s.used[tkh] = now.Add(s.ticketTTL)
	s.mu.Unlock()
	return sess, nil
}

// parseAuthHeader parses "ts.hex(hmac)".
func parseAuthHeader(h string) (int64, []byte, error) {
	i := strings.IndexByte(h, '.')
	if i <= 0 {
		return 0, nil, ErrBadAuth
	}
	var ts int64
	if _, err := fmt.Sscanf(h[:i], "%d", &ts); err != nil {
		return 0, nil, ErrBadAuth
	}
	mac, err := hex.DecodeString(h[i+1:])
	if err != nil || len(mac) != sha256.Size {
		return 0, nil, ErrBadAuth
	}
	return ts, mac, nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// cleanupLocked drops expired sessions and used-ticket entries.
// Caller holds s.mu.
func (s *Server) cleanupLocked(now time.Time) {
	if now.Sub(s.lastClean) < cleanupEvery {
		return
	}
	s.lastClean = now
	for id, sess := range s.sessions {
		if !now.Before(sess.Expires) {
			delete(s.sessions, id)
		}
	}
	for tkh, exp := range s.used {
		if !now.Before(exp) {
			delete(s.used, tkh)
		}
	}
	// Opportunistically pop expired entries off the eviction heap.
	for {
		it, ok := s.expHeap.top()
		if !ok || now.Before(it.exp) {
			break
		}
		heap.Pop(&s.expHeap)
	}
}

// evictLocked makes room when the session table is full by dropping
// the earliest-expiring sessions (amortized O(log n) via the heap).
// Caller holds s.mu.
func (s *Server) evictLocked() {
	for len(s.sessions) >= s.maxSessions {
		it, ok := s.expHeap.top()
		if !ok {
			// Heap exhausted but still over budget: drop an arbitrary
			// entry so the table never exceeds the cap.
			for id := range s.sessions {
				delete(s.sessions, id)
				break
			}
			return
		}
		heap.Pop(&s.expHeap)
		if _, still := s.sessions[it.id]; still {
			delete(s.sessions, it.id)
		}
	}
}
