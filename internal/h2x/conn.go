package h2x

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	// net not needed directly here.
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// writeQueueSize bounds in-flight frames awaiting the writer
	// goroutine.
	writeQueueSize = 256
	// connInitWin is the RFC 9113 connection-level initial window.
	connInitWin = 65535
	// maxPkts is a defensive cap on queued inbound DATA packets per
	// stream. The peer's un-replenished stream window bounds real
	// usage (≤ InitialWindowSize / frame size), so this only guards
	// against protocol violations.
	maxPkts = 4096
	// maxHeaderBytes bounds an incoming header block.
	maxHeaderBytes = 1 << 20
)

// ErrPreface is returned when the client preface is malformed.
var ErrPreface = errors.New("h2x: bad client preface")

// Conn is one HTTP/2 connection. Read and write paths each run on a
// single goroutine (readLoop, writerLoop); application code interacts
// with *Stream values and may do so from many goroutines.
type Conn struct {
	nc  net.Conn
	br  *bufio.Reader
	fr  *http2.Framer
	cfg Config

	hpenc    *hpack.Encoder
	hpdec    *hpack.Decoder
	encBuf   bytes.Buffer
	emitHdrs []hpack.HeaderField

	// onStream is the server-side hook for newly opened streams.
	onStream func(*Conn, *Stream)

	writeMu  sync.Mutex
	writerCh chan writeReq
	writeErr error

	mu              sync.Mutex
	cond            *sync.Cond
	closeNotify     chan struct{}
	gotPeerSettings bool
	connSendWindow  int64
	connRecvUnacked int64
	streams         map[uint32]*Stream
	pendingHdrs     map[uint32]*bytes.Buffer
	nextStreamID    uint32
	peerSettings    Settings
	remoteInitWin   int64
	maxPeerStreams  uint32
	closed          bool
	closeErr        error
	serverSide      bool
}

// writeReq is a queued frame write executed by the writer goroutine.
type writeReq struct {
	f   func() error
	err chan error
}

// newConn wires the framer and connection state. The read loop must
// not start before the server has consumed the client preface, so
// start() is called explicitly by the side-specific constructors.
func newConn(nc net.Conn, cfg Config, serverSide bool) (*Conn, error) {
	br := bufio.NewReaderSize(nc, 32<<10)
	fr := http2.NewFramer(nc, br)
	fr.SetMaxReadFrameSize(1 << 20)

	c := &Conn{
		nc:             nc,
		br:             br,
		fr:             fr,
		cfg:            cfg,
		writerCh:       make(chan writeReq, writeQueueSize),
		closeNotify:    make(chan struct{}),
		streams:        make(map[uint32]*Stream),
		pendingHdrs:    make(map[uint32]*bytes.Buffer),
		nextStreamID:   1,
		connSendWindow: connInitWin,
		remoteInitWin:  DefaultInitialWindowSize,
		maxPeerStreams: DefaultMaxConcurrentStreams,
		serverSide:     serverSide,
	}
	c.cond = sync.NewCond(&c.mu)
	c.hpdec = hpack.NewDecoder(maxHeaderBytes, func(f hpack.HeaderField) {
		c.emitHdrs = append(c.emitHdrs, f)
	})
	c.hpdec.SetMaxDynamicTableSize(64 << 10)
	c.hpenc = hpack.NewEncoder(&c.encBuf)
	return c, nil
}

func (c *Conn) start() {
	go c.writerLoop()
	go c.readLoop()
}

// ClientConn performs the client-side handshake (preface + SETTINGS)
// and returns a ready connection.
func ClientConn(nc net.Conn, cfg Config) (*Conn, error) {
	c, err := newConn(nc, cfg, false)
	if err != nil {
		return nil, err
	}
	c.start()
	if err := c.ClientPreface(); err != nil {
		c.failConn(err)
		return nil, err
	}
	if err := c.waitSettings(); err != nil {
		c.failConn(err)
		return nil, err
	}
	c.bumpConnWindow()
	return c, nil
}

// prefaceTimeout bounds how long the server waits for the client
// preface: a peer that connects and stalls (slowloris) must not pin a
// goroutine and socket forever.
const prefaceTimeout = 10 * time.Second

// ServerConn performs the server-side handshake (read preface, send
// SETTINGS, await peer SETTINGS) and returns a ready connection.
// onStream is invoked (on its own goroutine) for every client-opened
// stream whose headers have been fully received.
func ServerConn(nc net.Conn, cfg Config, onStream func(*Conn, *Stream)) (*Conn, error) {
	c, err := newConn(nc, cfg, true)
	if err != nil {
		return nil, err
	}
	c.onStream = onStream

	_ = c.nc.SetReadDeadline(time.Now().Add(prefaceTimeout))
	var pre = make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c.br, pre); err != nil {
		c.failConn(err)
		return nil, err
	}
	if string(pre) != http2.ClientPreface {
		c.failConn(ErrPreface)
		return nil, ErrPreface
	}
	_ = c.nc.SetReadDeadline(time.Time{}) // long-lived connection
	// Writer must run before we can send SETTINGS.
	go c.writerLoop()
	if err := c.sendFrame(func() error { return c.writeSettingsLocked(c.cfg.Settings) }); err != nil {
		c.failConn(err)
		return nil, err
	}
	go c.readLoop()
	if err := c.waitSettings(); err != nil {
		c.failConn(err)
		return nil, err
	}
	c.bumpConnWindow()
	return c, nil
}

// ClientPreface writes the h2 connection preface plus our SETTINGS.
func (c *Conn) ClientPreface() error {
	return c.sendFrame(func() error {
		if _, err := c.nc.Write([]byte(http2.ClientPreface)); err != nil {
			return err
		}
		return c.writeSettingsLocked(c.cfg.Settings)
	})
}

func (c *Conn) writeSettingsLocked(s Settings) error {
	sv := make([]http2.Setting, 0, 6)
	if s.HeaderTableSize != 0 {
		sv = append(sv, http2.Setting{ID: http2.SettingHeaderTableSize, Val: s.HeaderTableSize})
	}
	if s.EnablePush != nil {
		v := uint32(0)
		if *s.EnablePush {
			v = 1
		}
		sv = append(sv, http2.Setting{ID: http2.SettingEnablePush, Val: v})
	}
	if s.MaxConcurrentStreams != 0 {
		sv = append(sv, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: s.MaxConcurrentStreams})
	}
	if s.InitialWindowSize != 0 {
		sv = append(sv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: s.InitialWindowSize})
	}
	if s.MaxFrameSize != 0 {
		sv = append(sv, http2.Setting{ID: http2.SettingMaxFrameSize, Val: s.MaxFrameSize})
	}
	if s.MaxHeaderListSize != 0 {
		sv = append(sv, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: s.MaxHeaderListSize})
	}
	return c.fr.WriteSettings(sv...)
}

// bumpConnWindow raises the connection receive window we advertise.
func (c *Conn) bumpConnWindow() {
	if !c.cfg.SendConnWindowUpdate || c.cfg.ConnWindow <= connInitWin {
		return
	}
	c.sendFrame(func() error {
		return c.fr.WriteWindowUpdate(0, uint32(c.cfg.ConnWindow-connInitWin))
	})
}

// waitSettings blocks until the peer SETTINGS frame has been processed.
func (c *Conn) waitSettings() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for !c.closed && !c.gotPeerSettings {
		c.cond.Wait()
	}
	if c.closed {
		if c.closeErr != nil {
			return c.closeErr
		}
		return ErrConnClosed
	}
	return nil
}

// sendFrame queues f on the writer goroutine and waits for completion;
// it fails fast when the connection or writer has failed. The second
// select guards the queueing race: if the connection dies right after
// this frame was queued, we bail with the connection error and leave
// the request for the garbage collector (the Conn is torn down) rather
// than hang on a writer that already exited.
func (c *Conn) sendFrame(f func() error) error {
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = ErrConnClosed
		}
		return err
	}
	c.mu.Unlock()

	c.writeMu.Lock()
	if c.writeErr != nil {
		e := c.writeErr
		c.writeMu.Unlock()
		return e
	}
	c.writeMu.Unlock()

	req := writeReq{f: f, err: make(chan error, 1)}
	select {
	case c.writerCh <- req:
	case <-c.closeNotify:
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = ErrConnClosed
		}
		return err
	}
	select {
	case err := <-req.err:
		return err
	case <-c.closeNotify:
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = ErrConnClosed
		}
		return err
	}
}

// sendFrameAsync enqueues a control frame without waiting for it to
// complete. The read loop uses it so it can never block on its own
// writes (which could otherwise deadlock against a peer that only
// reads when we read). Errors surface via the sticky writer error.
func (c *Conn) sendFrameAsync(f func() error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.writeMu.Lock()
	if c.writeErr != nil {
		c.writeMu.Unlock()
		return
	}
	c.writeMu.Unlock()
	select {
	case c.writerCh <- writeReq{f: f, err: make(chan error, 1)}:
	default:
		// Queue saturated: drop the control frame; peers tolerate
		// missing SETTINGS/PING ACKs and recover via timeouts.
	}
}

func (c *Conn) writerLoop() {
	// Exits when failConn closes closeNotify. Requests that were queued
	// in the same instant are never closed over: their senders bail via
	// the closeNotify branch in sendFrame, so nobody hangs on this
	// goroutine. The goroutine never leaks.
	for {
		select {
		case req := <-c.writerCh:
			err := req.f()
			if err != nil {
				c.writeMu.Lock()
				if c.writeErr == nil {
					c.writeErr = err
				}
				c.writeMu.Unlock()
				c.failConn(err)
			}
			req.err <- err
		case <-c.closeNotify:
			return
		}
	}
}

func (c *Conn) readLoop() {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.failConn(err)
			return
		}
		if err := c.handleFrame(f); err != nil {
			c.failConn(err)
			return
		}
	}
}

// handleFrame dispatches one inbound frame. Errors are connection
// errors (the caller fails the connection).
func (c *Conn) handleFrame(f http2.Frame) error {
	switch fr := f.(type) {
	case *http2.SettingsFrame:
		if fr.IsAck() {
			return nil
		}
		return c.applyPeerSettings(fr)

	case *http2.WindowUpdateFrame:
		if fr.StreamID == 0 {
			c.mu.Lock()
			c.connSendWindow += int64(fr.Increment)
			c.cond.Broadcast()
			c.mu.Unlock()
			return nil
		}
		if st := c.getStream(fr.StreamID); st != nil {
			st.addSendWindow(int64(fr.Increment))
		}
		return nil

	case *http2.DataFrame:
		st := c.getStream(fr.StreamID)
		if st == nil {
			return nil // lenient: ignore data on unknown stream
		}
		payload := append([]byte(nil), fr.Data()...)
		// The whole frame length (incl. padding) counts against the
		// flow-control window; the stream replenishes on consumption.
		if err := st.pushData(payload, int(fr.Length), fr.StreamEnded()); err != nil {
			return err
		}
		return nil

	case *http2.HeadersFrame:
		return c.accHeaders(fr.StreamID, fr.HeaderBlockFragment(), fr.HeadersEnded(), fr.StreamEnded())

	case *http2.ContinuationFrame:
		return c.accHeaders(fr.StreamID, fr.HeaderBlockFragment(), fr.HeadersEnded(), false)

	case *http2.RSTStreamFrame:
		if st := c.getStream(fr.StreamID); st != nil {
			st.terminate(ErrReset)
		}
		return nil

	case *http2.PingFrame:
		if !fr.IsAck() {
			data := fr.Data
			c.sendFrameAsync(func() error { return c.fr.WritePing(true, data) })
		}
		return nil

	case *http2.GoAwayFrame:
		c.failConn(ErrConnClosed)
		return ErrConnClosed

	case *http2.PriorityFrame, *http2.PushPromiseFrame, *http2.UnknownFrame:
		return nil // ignored for v1 (server push disabled)
	}
	return nil
}

// accHeaders accumulates header-block fragments and, once the block is
// complete, routes it to a new or existing stream.
func (c *Conn) accHeaders(streamID uint32, fragment []byte, endHeaders, streamEnded bool) error {
	c.mu.Lock()
	buf, ok := c.pendingHdrs[streamID]
	if !ok {
		buf = &bytes.Buffer{}
		c.pendingHdrs[streamID] = buf
	}
	_, _ = buf.Write(fragment)
	done := endHeaders
	c.mu.Unlock()

	if !done {
		return nil
	}

	// Decode the full block with the persistent HPACK state.
	c.emitHdrs = nil
	block := buf.Bytes()
	if _, err := c.hpdec.Write(block); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.pendingHdrs, streamID)
	hdrs := append([]hpack.HeaderField(nil), c.emitHdrs...)
	st := c.streams[streamID]
	if st == nil && c.serverSide && streamID%2 == 1 {
		if len(c.streams) >= int(c.cfg.Settings.MaxConcurrentStreams) {
			c.mu.Unlock()
			c.sendFrameAsync(func() error {
				return c.fr.WriteRSTStream(streamID, http2.ErrCodeRefusedStream)
			})
			return nil
		}
		st = newStream(c, streamID, c.remoteInitWin)
		c.streams[streamID] = st
		c.mu.Unlock()
		st.hdrs = hdrs
		if streamEnded {
			st.markRemoteEnd()
		}
		if c.onStream != nil {
			go c.onStream(c, st)
		}
		return nil
	}
	c.mu.Unlock()

	if st != nil {
		st.hdrs = hdrs
		if streamEnded {
			st.markRemoteEnd()
		}
	}
	return nil
}

// applyPeerSettings applies the peer SETTINGS and ACKs them.
func (c *Conn) applyPeerSettings(fr *http2.SettingsFrame) error {
	var initDelta int64
	var hdrTable uint32
	c.mu.Lock()
	err := fr.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			initDelta = int64(s.Val) - c.remoteInitWin
			c.remoteInitWin = int64(s.Val)
		case http2.SettingMaxConcurrentStreams:
			c.maxPeerStreams = s.Val
		case http2.SettingHeaderTableSize:
			hdrTable = s.Val
		}
		return nil
	})
	if err == nil {
		c.gotPeerSettings = true
		if initDelta != 0 {
			for _, st := range c.streams {
				st.addSendWindowLocked(initDelta)
			}
		}
		if hdrTable != 0 {
			c.peerSettings.HeaderTableSize = hdrTable
		}
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}

	if hdrTable > 0 {
		c.hpenc.SetMaxDynamicTableSize(hdrTable)
	}
	c.sendFrameAsync(func() error { return c.fr.WriteSettingsAck() })
	return nil
}

func (c *Conn) getStream(id uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *Conn) putStream(st *Stream) {
	c.mu.Lock()
	c.streams[st.id] = st
	c.mu.Unlock()
}

func (c *Conn) delStream(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// writeHeaders encodes and sends a HEADERS frame (single header block;
// no CONTINUATION needed for our small blocks).
func (c *Conn) writeHeaders(streamID uint32, hf []hpack.HeaderField, endStream bool) error {
	return c.sendFrame(func() error {
		c.encBuf.Reset()
		for _, f := range hf {
			if err := c.hpenc.WriteField(f); err != nil {
				return err
			}
		}
		return c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: c.encBuf.Bytes(),
			EndStream:     endStream,
			EndHeaders:    true,
		})
	})
}

// failConn tears the connection down: notify writers/readers, close the
// socket and terminate every stream.
func (c *Conn) failConn(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = err
	}
	streams := make([]*Stream, 0, len(c.streams))
	for _, st := range c.streams {
		streams = append(streams, st)
	}
	close(c.closeNotify)
	c.cond.Broadcast()
	c.mu.Unlock()

	_ = c.nc.Close()
	for _, st := range streams {
		st.terminate(ErrConnClosed)
	}
}

// GoAway sends a GOAWAY frame (best effort) and closes the connection.
func (c *Conn) GoAway() {
	_ = c.sendFrame(func() error {
		return c.fr.WriteGoAway(0, http2.ErrCodeNo, nil)
	})
	c.failConn(ErrConnClosed)
}

// PeerSettings returns the settings advertised by the peer.
func (c *Conn) PeerSettings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerSettings
}

// Closed reports whether the connection has failed.
func (c *Conn) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// ReadErr returns the connection-level failure reason (nil if alive).
func (c *Conn) ReadErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// Done is closed when the connection fails or is closed.
func (c *Conn) Done() <-chan struct{} { return c.closeNotify }
