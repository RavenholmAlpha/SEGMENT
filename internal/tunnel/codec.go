// Package tunnel wires the pieces together: HTTP/2 fronting
// (internal/h2x) + inner Segment frames (internal/segment) +
// authentication (internal/auth). It provides the server-side
// connection manager (control stream, 0-RTT resume, full handshake,
// per-channel relay) and the client-side dialer that exposes tunneled
// TCP connections and UDP flows to the local SOCKS5/TUN ingress.
package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"segment/internal/h2x"
	"segment/internal/segment"
)

// ErrAuthRequired is returned when the connection has no established
// session yet.
var ErrAuthRequired = errors.New("tunnel: auth required")

// Codec adapts one h2x stream to Segment frames: every h2 DATA payload
// is exactly one Segment frame (see docs/design.md §4.1).
type Codec struct {
	st      *h2x.Stream
	s       *segment.Session
	sendDir segment.Direction
	recvDir segment.Direction
}

// NewCodec builds a frame codec for one tunnel stream. sendDir is the
// direction of our own writes, recvDir the direction of the peer's.
func NewCodec(st *h2x.Stream, s *segment.Session, sendDir, recvDir segment.Direction) *Codec {
	return &Codec{st: st, s: s, sendDir: sendDir, recvDir: recvDir}
}

// ReadFrame returns the next decoded Segment frame. It returns io.EOF
// once the peer closes the stream.
func (c *Codec) ReadFrame() (segment.Frame, error) {
	p, end, err := c.st.ReadData()
	if err != nil {
		return segment.Frame{}, err
	}
	if end {
		return segment.Frame{}, io.EOF
	}
	return c.s.Decode(c.recvDir, c.st.ID(), p)
}

// WriteFrame encodes and sends one Segment frame. padTo, if > 0, is the
// target on-wire size (padding for size normalization). Encoding runs
// zero-allocation against a pooled buffer; the pooled memory is
// returned once the frame has been handed to h2.
func (c *Codec) WriteFrame(ft segment.FrameType, fl segment.Flags, payload []byte, padTo int) error {
	bp := encodeBufPool.Get().(*[]byte)
	b := *bp
	defer func() { *bp = b[:cap(b)]; encodeBufPool.Put(bp) }()
	out, err := c.s.EncodeAt(c.sendDir, c.st.ID(), ft, fl, payload, padTo, b)
	if err != nil {
		return err
	}
	return c.st.WriteChunk(out, false)
}

// poolBufSize covers the largest on-wire frame: DataChunk data payload
// (16000) + data length prefix (2) + GCM tag (16) + frame header (4) +
// worst-case h2 pad headroom. The pool keeps one buffer per active
// frame being encoded.
const poolBufSize = 16 << 10

var encodeBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, poolBufSize)
		return &b
	},
}

// Conn is the client-side view of one tunneled TCP connection. It
// implements io.ReadWriteCloser so SOCKS5/TUN can treat it like a local
// net.Conn.
type Conn struct {
	codec     *Codec
	io        sync.Mutex // serializes ReadFrame (one reader at a time)
	ow        sync.Mutex // serializes writes (frame order)
	closeOnce sync.Once
	closed    chan struct{}
}

// NewConn wraps a client-side stream in a tunneled TCP connection.
func NewConn(codec *Codec) *Conn {
	return &Conn{codec: codec, closed: make(chan struct{})}
}

// Read returns one tunneled data chunk (up to one Segment frame's
// payload). It is safe for a single reader.
func (c *Conn) Read(p []byte) (int, error) {
	for {
		f, err := c.codec.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
		switch f.Type {
		case segment.FrameData:
			data, err := segment.ParseDataPayload(f.Payload)
			if err != nil {
				return 0, err
			}
			n := copy(p, data)
			return n, nil
		case segment.FrameClose:
			return 0, io.EOF
		default:
			// Ignore control frames interleaved on data streams.
			continue
		}
	}
}

// Write sends one data chunk through the tunnel.
func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, errors.New("tunnel: connection closed")
	default:
	}
	c.ow.Lock()
	defer c.ow.Unlock()
	err := c.codec.WriteFrame(segment.FrameData, 0, segment.BuildDataPayload(p), 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close terminates the tunneled connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.codec.WriteFrame(segment.FrameClose, 0, segment.BuildClosePayload(0), 0)
		_ = c.codec.st.CloseSend()
	})
	return nil
}

// LocalAddr/RemoteAddr/Set*Deadline keep net.Conn's interface happy
// for SOCKS5 (deadlines are set on the underlying h2 connection).
func (c *Conn) LocalAddr() net.Addr                { return netAddr{} }
func (c *Conn) RemoteAddr() net.Addr               { return netAddr{} }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

// netAddr is a placeholder address; SOCKS5 does not use it.
type netAddr struct{}

func (netAddr) Network() string { return "segment" }
func (netAddr) String() string  { return "segment-tunnel" }
