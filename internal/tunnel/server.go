package tunnel

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"

	"segment/internal/auth"
	"segment/internal/h2x"
	"segment/internal/segment"
)

// Tunnel markers: a three-header combination that real Chrome 120+
// media requests carry (MSE/HLS/DASH segment fetches always send
// sec-fetch-dest=empty, sec-fetch-mode=cors, priority=u=1,i). The
// tunnel client sends exactly this shape, so tunnel streams are
// indistinguishable from ordinary media fetches at the header level;
// matching requires all three values, which ordinary browsing only
// reproduces for media fetches to //videos/*/seg-*.m4s paths — an
// acceptable collision (the fake site serves those as media anyway).
// No custom header name is ever sent on the wire.
const (
	markerDestHeader = "sec-fetch-dest"
	markerDestValue  = "empty"
	markerModeHeader = "sec-fetch-mode"
	markerModeValue  = "cors"
	markerPriHeader  = "priority"
	markerPriValue   = "u=1, i"
)

// hasTunnelMarkers reports whether the stream's headers carry the
// tunnel marker combination.
func hasTunnelMarkers(hdrs []hpack.HeaderField) bool {
	dest, mode, pri := false, false, false
	for _, h := range hdrs {
		switch h.Name {
		case markerDestHeader:
			dest = h.Value == markerDestValue
		case markerModeHeader:
			mode = h.Value == markerModeValue
		case markerPriHeader:
			pri = h.Value == markerPriValue
		}
	}
	return dest && mode && pri
}

// DataChunk is the maximum tunneled data payload inside one h2 DATA
// frame: the peer's default max frame size (16384) minus the 9-byte h2
// frame header, the pad-length byte, worst-case random pad (255), the
// Segment frame header (4), the data length prefix (2) and the GCM tag
// (16): 16384 - 9 - 1 - 255 - 22 = 16097 -> rounded to 16000. Each
// Segment frame therefore rides in a single h2 DATA frame.
const DataChunk = 16000

const (
	// udpIdleTimeout reaps idle UDP channels.
	udpIdleTimeout = 30 * time.Second
)

const (
	controlPath    = "/videos/channel/sessions-0.m3u8"
	resumeResponse = "[]"
)

// DialFunc dials a target; the tunnel server's outbound gateway.
type DialFunc func(network, addr string) (net.Conn, error)

// FakeSiteResponder renders a request through the configured cover site. It
// stays deliberately narrow so tunnel admission can fall back to the cover
// response without depending on the fakesite package.
type FakeSiteResponder func(*h2x.Stream)

// ConnState is the per-connection tunnel state on the server.
type ConnState struct {
	auth   *auth.Server
	dial   DialFunc
	pacing Pacing
	fake   FakeSiteResponder

	ready chan struct{}
	once  sync.Once
	err   error
	sess  *segment.Session

	udpMu   sync.Mutex
	udpOpen map[uint32]struct{}
}

// StateFor returns (creating on first use) the tunnel state bound to
// one h2 connection.
func StateFor(h2c *h2x.Conn, as *auth.Server, dial DialFunc, pacing Pacing, fake FakeSiteResponder) *ConnState {
	if v, ok := connStates.Load(h2c); ok {
		return v.(*ConnState)
	}
	cs := &ConnState{
		auth:    as,
		dial:    dial,
		pacing:  pacing,
		fake:    fake,
		ready:   make(chan struct{}),
		udpOpen: make(map[uint32]struct{}),
	}
	actual, _ := connStates.LoadOrStore(h2c, cs)
	return actual.(*ConnState)
}

var connStates sync.Map // *h2x.Conn -> *ConnState

// Release drops the per-connection state when the h2 connection ends.
func Release(h2c *h2x.Conn) {
	connStates.Delete(h2c)
}

// ErrFakeSite is returned by HandleStream when the stream must be
// served by the fake site instead of the tunnel.
var ErrFakeSite = errors.New("tunnel: serve fake site instead")

// HandleStream returns nil once it fully handled the stream (tunnel,
// auth, control). Non-nil errors other than ErrFakeSite are fatal to
// the connection.
func (cs *ConnState) HandleStream(st *h2x.Stream) error {
	hdrs := st.Headers()
	path := headerValue(hdrs, ":path")
	isTunnel := hasTunnelMarkers(hdrs)

	if isTunnel && !cs.Ready() {
		return ErrFakeSite
	}
	if isTunnel {
		if path == controlPath {
			go cs.handleControl(st)
			return nil
		}
		go cs.handleTunnel(st)
		return nil
	}
	if path == "/api/v1/telemetry" && headerValue(hdrs, ":method") == "POST" {
		go cs.handleAuthPost(st)
		return nil
	}
	return ErrFakeSite
}

// Ready reports whether this connection has an established tunnel session.
// Closing ready synchronizes the session fields written by establish/readyFail
// with all later stream handlers.
func (cs *ConnState) Ready() bool {
	select {
	case <-cs.ready:
		return cs.err == nil && cs.sess != nil
	default:
		return false
	}
}

// handleControl services the encrypted keepalive/ack stream. Admission has
// already verified that a session is established, so no unauthenticated media
// request can reach this handler.
func (cs *ConnState) handleControl(st *h2x.Stream) {
	if err := cs.writeTunnelHeaders(st); err != nil {
		return
	}
	codec := NewCodec(st, cs.sess, segment.DirServerToClient, segment.DirClientToServer)
	cs.keepaliveLoop(codec)
}

// keepaliveLoop answers FRAME_KEEPALIVE with FRAME_ACK until the stream
// or connection dies.
func (cs *ConnState) keepaliveLoop(codec *Codec) {
	for {
		f, err := codec.ReadFrame()
		if err != nil {
			return
		}
		switch f.Type {
		case segment.FrameKeepalive:
			ts, err := segment.ParseKeepalivePayload(f.Payload)
			if err != nil {
				return
			}
			if err := codec.WriteFrame(segment.FrameAck, 0, segment.BuildAckPayload(ts), 0); err != nil {
				return
			}
		}
	}
}

// handleAuthPost completes either the full PSK handshake or ticket resume on
// the ordinary POST /api/v1/telemetry path, then establishes the connection
// session. Any missing or invalid proof receives the configured fake site.
func (cs *ConnState) handleAuthPost(st *h2x.Stream) {
	hdr := headerValue(st.Headers(), "x-sg-c")
	body, err := readAll(st)
	if err != nil {
		cs.serveFake(st)
		return
	}
	if hdr == "" {
		cs.handleResumePost(st, body)
		return
	}
	sess, connNonce, err := cs.auth.VerifyAuth(hdr, body)
	if err != nil {
		cs.serveFake(st)
		return
	}
	ticket, err := cs.auth.IssueTicket(sess)
	if err != nil {
		cs.serveFake(st)
		return
	}
	resp := make([]byte, 0, len(ticket)+32)
	resp = append(resp, ticket...)
	resp = append(resp, sess.Key[:]...)
	// Establish the connection session before answering: the client's
	// Establish() returns as soon as it reads this response, and any
	// stream it opens (including control-stream keepalives) must find a
	// ready session on the server side.
	cs.establish(connNonce, sess.Key[:])
	if err := st.WriteHeaders([]hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: strconv.Itoa(len(resp))},
	}, false); err != nil {
		return
	}
	if err := st.WriteData(resp, true); err != nil {
		return
	}
}

func (cs *ConnState) handleResumePost(st *h2x.Stream, body []byte) {
	sess, err := cs.auth.Resume(body)
	if err != nil {
		cs.serveFake(st)
		return
	}
	connNonce := body[:segment.ConnNonceLen]
	cs.establish(connNonce, sess.Key[:])
	if err := st.WriteHeaders([]hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/json"},
		{Name: "content-length", Value: strconv.Itoa(len(resumeResponse))},
	}, false); err != nil {
		return
	}
	_ = st.WriteData([]byte(resumeResponse), true)
}

// serveFake uses the fronting layer's configured responder for failures that
// are discovered after HandleStream returned. At this point the tunnel package
// cannot return ErrFakeSite to its caller, so the callback preserves the same
// cover-site boundary without importing fakesite here.
func (cs *ConnState) serveFake(st *h2x.Stream) {
	if cs.fake != nil {
		cs.fake(st)
	}
}

// establish creates the per-connection Segment session and unblocks
// tunnel streams.
func (cs *ConnState) establish(connNonce, sessionKey []byte) {
	s, err := segment.NewSession(connNonce)
	if err == nil {
		err = s.Establish(sessionKey)
	}
	cs.once.Do(func() {
		if err != nil {
			cs.err = err
		}
		cs.sess = s
		close(cs.ready)
	})
}

// handleTunnel services a data stream: wait for the session, read the
// FRAME_OPEN, then relay to the target.
func (cs *ConnState) handleTunnel(st *h2x.Stream) {
	if err := cs.writeTunnelHeaders(st); err != nil {
		return
	}
	codec := NewCodec(st, cs.sess, segment.DirServerToClient, segment.DirClientToServer)

	// Randomize h2 pad lengths on this stream's outbound frames.
	st.Pad = PadLen

	f, err := codec.ReadFrame()
	if err != nil {
		return
	}
	if f.Type != segment.FrameOpen {
		_ = st.Reset(0x1)
		return
	}
	addr, port, err := segment.ParseOpenPayload(f.Payload)
	if err != nil {
		_ = st.Reset(0x1)
		return
	}
	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	if f.Flags&segment.FlagUDP != 0 {
		cs.relayUDP(codec, target)
		return
	}
	cs.relayTCP(codec, target)
}

// writeTunnelHeaders emits the normal media response header block that must
// precede every authenticated tunnel/control DATA frame.
func (cs *ConnState) writeTunnelHeaders(st *h2x.Stream) error {
	return st.WriteHeaders([]hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "video/mp4"},
	}, false)
}

// relayTCP pipes the tunnel stream to a TCP socket.
func (cs *ConnState) relayTCP(codec *Codec, target string) {
	conn, err := cs.dial("tcp", target)
	if err != nil {
		_ = codec.WriteFrame(segment.FrameClose, segment.FlagRST, segment.BuildClosePayload(1), 0)
		return
	}
	defer conn.Close()
	defer codec.WriteFrame(segment.FrameClose, 0, segment.BuildClosePayload(0), 0)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Close the socket when the stream ends: this unblocks the
		// socket->stream pump below and ripples the close back to the
		// client (echo of FRAME_CLOSE).
		defer conn.Close()
		for {
			f, err := codec.ReadFrame()
			if err != nil {
				return
			}
			switch f.Type {
			case segment.FrameData:
				data, err := segment.ParseDataPayload(f.Payload)
				if err != nil {
					return
				}
				if _, err := conn.Write(data); err != nil {
					return
				}
				if f.Flags&segment.FlagFIN != 0 {
					if tc, ok := conn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
				}
			case segment.FrameClose:
				return
			}
		}
	}()

	buf := make([]byte, DataChunk)
	pacer := NewPacedWriter(cs.pacing, func(b []byte) error {
		return codec.WriteFrame(segment.FrameData, 0, segment.BuildDataPayload(b), 0)
	})
readLoop:
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := pacer.Write(buf[:n]); werr != nil {
				break readLoop
			}
		}
		if err != nil {
			break readLoop
		}
	}
	// Wake the stream->socket pump: it can be blocked in ReadFrame when
	// the peer is idle, which would otherwise deadlock the Wait below
	// and leak this goroutine and the socket until the connection dies.
	codec.st.CloseRead()
	// Wait for the stream->socket pump so the close back to the client
	// is delivered after the socket has been torn down.
	wg.Wait()
	// Finish the h2 half so the stream gets reaped (H3) and the peer
	// observes an orderly EOF after the application-level FRAME_CLOSE.
	_ = codec.st.CloseSend()
}

// relayUDP pipes the tunnel stream to a connected UDP socket; each
// FRAME_DATA carries exactly one datagram.
func (cs *ConnState) relayUDP(codec *Codec, target string) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		_ = codec.WriteFrame(segment.FrameClose, segment.FlagRST, segment.BuildClosePayload(1), 0)
		return
	}
	defer conn.Close()
	defer codec.WriteFrame(segment.FrameClose, 0, segment.BuildClosePayload(0), 0)

	idle := time.AfterFunc(udpIdleTimeout, func() {
		_ = conn.Close()
	})
	// Only the stream->socket pump resets the idle timer: time.Timer.Reset
	// must not be called concurrently from two goroutines (or racing the
	// AfterFunc). Session liveness is judged by client activity, which is
	// exactly what that pump observes.
	resetIdle := func() { idle.Reset(udpIdleTimeout) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer conn.Close() // unblock the socket->stream pump on stream end
		for {
			f, err := codec.ReadFrame()
			if err != nil {
				return
			}
			switch f.Type {
			case segment.FrameData:
				dgram, err := segment.ParseDataPayload(f.Payload)
				if err != nil {
					return
				}
				if _, err := conn.Write(dgram); err != nil {
					return
				}
				resetIdle()
			case segment.FrameClose:
				return
			}
		}
	}()

	buf := make([]byte, DataChunk)
readLoop:
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := codec.WriteFrame(segment.FrameData, 0, segment.BuildDataPayload(buf[:n]), 0); werr != nil {
				break readLoop
			}
		}
		if err != nil {
			break readLoop
		}
	}
	codec.st.CloseRead()
	wg.Wait()
	_ = codec.st.CloseSend()
}

// authBodyLimit caps an unauthenticated request body: the auth blob is
// ~100 bytes, so anything larger is almost certainly an unauthenticated
// attempt to exhaust server memory (the h2 flow-control window would by
// itself admit several MB of body without this cap).
const authBodyLimit = 64 << 10

// readAll drains a stream until END_STREAM, bounded by authBodyLimit.
func readAll(st *h2x.Stream) ([]byte, error) {
	buf := make([]byte, 0, 256)
	for {
		p, end, err := st.ReadData()
		if err != nil {
			return nil, err
		}
		if p != nil {
			buf = append(buf, p...)
			if len(buf) > authBodyLimit {
				return nil, errors.New("tunnel: request body too large")
			}
		}
		if end {
			return buf, nil
		}
	}
}

func headerValue(hdrs []hpack.HeaderField, name string) string {
	for _, h := range hdrs {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}
