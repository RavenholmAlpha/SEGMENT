package h2x

import (
	"errors"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// dataPkt is one received DATA frame payload (padding stripped) plus
// its wire length (used for flow-control replenishment) and the
// END_STREAM flag it carried.
type dataPkt struct {
	data    []byte
	wireLen int
	end     bool
}

// Stream is one HTTP/2 stream with frame-granular I/O. ReadData
// returns exactly one DATA frame payload per call, which maps 1:1 onto
// Segment inner frames. WriteData is flow-controlled and may block
// until the peer grants window.
type Stream struct {
	c    *Conn
	id   uint32
	hdrs []hpack.HeaderField

	// Pad, when set, returns the number of random pad bytes (0..255)
	// appended to each outbound DATA frame. The disguise layer uses it
	// for size jitter; payload sizes themselves are normalized at the
	// Segment layer.
	Pad func(payloadLen int) int

	// Inbound state (guarded by mu).
	pktCh       chan dataPkt
	mu          sync.Mutex
	cond        *sync.Cond
	remoteEnd   bool
	localEnd    bool
	readClosed  bool
	terminated  bool
	termErr     error
	recvUnacked int64

	// Outbound flow-control state (guarded by c.mu).
	sendWindow int64
}

func newStream(c *Conn, id uint32, initWin int64) *Stream {
	st := &Stream{
		c:          c,
		id:         id,
		pktCh:      make(chan dataPkt, maxPkts),
		sendWindow: initWin,
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// ID returns the h2 stream id.
func (st *Stream) ID() uint32 { return st.id }

// Headers returns the headers received on this stream.
func (st *Stream) Headers() []hpack.HeaderField { return st.hdrs }

// WriteHeaders sends the response or request header block.
func (st *Stream) WriteHeaders(hf []hpack.HeaderField, endStream bool) error {
	if err := st.c.writeHeaders(st.id, hf, endStream); err != nil {
		return err
	}
	if endStream {
		st.setLocalEnd()
	}
	return nil
}

// WriteData sends p as one or more DATA frames, honoring flow control.
// When endStream is set, the last frame carries END_STREAM.
func (st *Stream) WriteData(p []byte, endStream bool) error {
	max := int(st.c.cfg.MaxFrameSize) - 9 // 9-byte h2 frame header
	if st.Pad != nil {
		// Leave room for the pad-length byte and worst-case padding so
		// the frame never exceeds the peer's max frame size.
		max -= 1 + 255
	}
	if max < 0 {
		max = 0
	}
	for {
		var payload []byte
		fin := false
		switch n := len(p); {
		case n == 0:
			if !endStream {
				return nil
			}
			fin = true // empty closing DATA frame
		case n > max:
			payload = p[:max]
			p = p[max:]
		default:
			payload = p
			p = nil
			fin = endStream
		}
		pad := 0
		if st.Pad != nil {
			pad = st.Pad(len(payload))
			if pad < 0 {
				pad = 0
			}
			if pad > 255 {
				pad = 255
			}
		}
		if err := st.waitSendWindow(int64(len(payload) + pad)); err != nil {
			return err
		}
		err := st.c.sendFrame(func() error {
			if pad > 0 {
				// Zero padding: matches real browsers, which pad with
				// zeros; only the pad *length* varies for disguise.
				pb := make([]byte, pad)
				return st.c.fr.WriteDataPadded(st.id, fin, payload, pb)
			}
			return st.c.fr.WriteData(st.id, fin, payload)
		})
		if err != nil {
			return err
		}
		if fin {
			st.setLocalEnd()
			return nil
		}
		if len(payload) == 0 {
			return nil
		}
	}
}

// WriteChunk sends a single DATA frame (≤ config.MaxFrameSize) without
// splitting, blocking until flow-control window is available.
func (st *Stream) WriteChunk(p []byte, endStream bool) error {
	if len(p) > int(st.c.cfg.MaxFrameSize) {
		return ErrFlowControl
	}
	pad := 0
	if st.Pad != nil {
		pad = st.Pad(len(p))
	}
	if err := st.waitSendWindow(int64(len(p) + pad)); err != nil {
		return err
	}
	err := st.c.sendFrame(func() error {
		if pad > 0 {
			pb := make([]byte, pad) // zero padding, matching browsers
			return st.c.fr.WriteDataPadded(st.id, endStream, p, pb)
		}
		return st.c.fr.WriteData(st.id, endStream, p)
	})
	if err != nil {
		return err
	}
	if endStream {
		st.setLocalEnd()
	}
	return nil
}

// CloseSend sends an empty DATA frame with END_STREAM.
func (st *Stream) CloseSend() error { return st.WriteData(nil, true) }

// Reset aborts the stream in both directions.
func (st *Stream) Reset(code http2.ErrCode) error {
	err := st.c.sendFrame(func() error { return st.c.fr.WriteRSTStream(st.id, code) })
	st.terminate(ErrReset)
	return err
}

// ErrReadClosed is returned by ReadData after CloseRead.
var ErrReadClosed = errors.New("h2x: read side closed")

// CloseRead aborts the receive side of this stream locally: any reader
// blocked in ReadData (e.g. a relay pump whose peer went idle) wakes up
// with ErrReadClosed. Inbound frames after CloseRead are discarded by
// the caller of ReadData; the stream itself stays open for the peer's
// half-close bookkeeping.
func (st *Stream) CloseRead() {
	st.mu.Lock()
	st.readClosed = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

// ReadData returns the next DATA frame payload. endStream is true for
// the final frame; after that the stream yields (nil, true, nil) like
// io.EOF. It returns ErrReset/ErrConnClosed when the stream or
// connection dies, and ErrReadClosed after CloseRead. Errors never
// occur here.
func (st *Stream) ReadData() ([]byte, bool, error) {
	st.mu.Lock()
	for {
		if st.termErr != nil {
			err := st.termErr
			st.mu.Unlock()
			return nil, false, err
		}
		if st.readClosed {
			st.mu.Unlock()
			return nil, false, ErrReadClosed
		}
		select {
		case pkt, ok := <-st.pktCh:
			if !ok {
				st.mu.Unlock()
				return nil, false, ErrConnClosed
			}
			st.recvUnacked += int64(pkt.wireLen)
			consumed := int64(pkt.wireLen)
			end := pkt.end
			st.mu.Unlock()
			st.replenish(consumed)
			if end {
				st.pruneIfDone()
			}
			return pkt.data, end, nil
		default:
		}
		if st.remoteEnd {
			st.mu.Unlock()
			return nil, true, nil
		}
		st.cond.Wait()
	}
}

// pushData queues an inbound DATA frame; called from the read loop.
// A full queue means the peer exceeded its advertised window — except
// for abandoned streams (CloseRead), whose inbound frames are dropped
// outright: a peer that keeps writing to a stream the application gave
// up on must never be able to overflow the queue and kill the whole
// connection via ErrFlowControl.
func (st *Stream) pushData(data []byte, wireLen int, end bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.terminated || st.readClosed {
		return nil
	}
	select {
	case st.pktCh <- dataPkt{data: data, wireLen: wireLen, end: end}:
	default:
		return ErrFlowControl
	}
	if end {
		st.remoteEnd = true
	}
	st.cond.Broadcast()
	return nil
}

// markRemoteEnd records END_STREAM for header-only streams.
func (st *Stream) markRemoteEnd() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.terminated {
		return
	}
	st.remoteEnd = true
	st.cond.Broadcast()
}

func (st *Stream) setLocalEnd() {
	st.mu.Lock()
	st.localEnd = true
	st.mu.Unlock()
	st.pruneIfDone()
}

func (st *Stream) pruneIfDone() {
	st.mu.Lock()
	done := st.localEnd && st.remoteEnd
	st.mu.Unlock()
	if done {
		st.c.delStream(st.id)
	}
}

// replenish grants the peer flow-control window for consumed bytes.
func (st *Stream) replenish(consumed int64) {
	var streamUpdate, connUpdate int64

	st.mu.Lock()
	if st.recvUnacked >= st.c.cfg.StreamWindowChunk {
		streamUpdate = st.recvUnacked
		st.recvUnacked = 0
	}
	st.mu.Unlock()

	c := st.c
	c.mu.Lock()
	if streamUpdate > 0 {
		c.connRecvUnacked += streamUpdate
	}
	if c.connRecvUnacked >= c.cfg.ConnWindowChunk {
		connUpdate = c.connRecvUnacked
		c.connRecvUnacked = 0
	}
	c.mu.Unlock()

	if streamUpdate > 0 {
		_ = c.sendFrame(func() error {
			return c.fr.WriteWindowUpdate(st.id, uint32(streamUpdate))
		})
	}
	if connUpdate > 0 {
		_ = c.sendFrame(func() error {
			return c.fr.WriteWindowUpdate(0, uint32(connUpdate))
		})
	}
}

// waitSendWindow blocks until n bytes of send window are available on
// both the connection and the stream, then consumes them.
func (st *Stream) waitSendWindow(n int64) error {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.connSendWindow < n || st.sendWindow < n {
		if c.closed {
			if c.closeErr != nil {
				return c.closeErr
			}
			return ErrConnClosed
		}
		c.cond.Wait()
	}
	c.connSendWindow -= n
	st.sendWindow -= n
	return nil
}

// addSendWindow grants stream send window (WINDOW_UPDATE received).
func (st *Stream) addSendWindow(delta int64) {
	c := st.c
	c.mu.Lock()
	st.sendWindow += delta
	c.cond.Broadcast()
	c.mu.Unlock()
}

// addSendWindowLocked grants stream send window; caller holds c.mu
// (SETTINGS_INITIAL_WINDOW_SIZE deltas).
func (st *Stream) addSendWindowLocked(delta int64) {
	st.sendWindow += delta
}

// terminate fails the stream (RST, GOAWAY, connection failure).
func (st *Stream) terminate(err error) {
	st.mu.Lock()
	if st.terminated {
		st.mu.Unlock()
		return
	}
	st.terminated = true
	if st.termErr == nil {
		st.termErr = err
	}
	close(st.pktCh)
	st.cond.Broadcast()
	st.mu.Unlock()
	st.c.delStream(st.id)
}
