package h2x

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const testTimeout = 15 * time.Second

// startPair runs the server in a goroutine and returns the client conn.
func startPair(t *testing.T, serverCfg, clientCfg Config, onStream func(*Conn, *Stream)) (*Conn, *Conn) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	_ = serverSide.SetDeadline(time.Now().Add(testTimeout))
	_ = clientSide.SetDeadline(time.Now().Add(testTimeout))

	type result struct {
		conn *Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ServerConn(serverSide, serverCfg, onStream)
		done <- result{c, err}
	}()
	cli, err := ClientConn(clientSide, clientCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := <-done
	if r.err != nil {
		cli.GoAway()
		t.Fatalf("server handshake: %v", r.err)
	}
	t.Cleanup(func() {
		cli.GoAway()
		r.conn.GoAway()
	})
	return cli, r.conn
}

func echoHandler(_ *Conn, st *Stream) {
	_ = st.WriteHeaders([]hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/octet-stream"},
	}, false)
	for {
		p, end, err := st.ReadData()
		if err != nil {
			return
		}
		if end {
			_ = st.WriteData(p, true)
			return
		}
		if err := st.WriteData(p, false); err != nil {
			return
		}
	}
}

func TestHandshakeAndEcho(t *testing.T) {
	cfg := DefaultConfig()
	cli, _ := startPair(t, cfg, cfg, echoHandler)

	st, err := cli.NewStream([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/echo"},
		{Name: "content-type", Value: "application/octet-stream"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteData([]byte("hello segment"), false); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseSend(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatalf("read: %v (conn: %v)", err, cli.ReadErr())
		}
		if p != nil {
			got = append(got, p...)
		}
		if end {
			break
		}
	}
	if string(got) != "hello segment" {
		t.Fatalf("echo mismatch: %q", got)
	}
}

func TestFrameBoundariesPreserved(t *testing.T) {
	cfg := DefaultConfig()
	cli, _ := startPair(t, cfg, cfg, func(_ *Conn, st *Stream) {
		var got [][]byte
		_ = st.WriteHeaders([]hpack.HeaderField{{Name: ":status", Value: "200"}}, false)
		for {
			p, end, err := st.ReadData()
			if err != nil {
				return
			}
			got = append(got, p)
			if end {
				break
			}
		}
		// Echo each frame in one DATA frame of its own.
		for _, chunk := range got {
			if len(chunk) > 0 {
				if err := st.WriteData(chunk, false); err != nil {
					return
				}
			}
		}
		_ = st.CloseSend()
	})

	st, err := cli.NewStream([]hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/x"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.WriteData([]byte("ab"), false)
	_ = st.WriteData([]byte("cd"), false)
	_ = st.CloseSend()

	var frames [][]byte
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			frames = append(frames, p)
		}
		if end {
			break
		}
	}
	if len(frames) != 2 || string(frames[0]) != "ab" || string(frames[1]) != "cd" {
		t.Fatalf("frame boundaries lost: %q", frames)
	}
}

func TestPaddingStripped(t *testing.T) {
	cfg := DefaultConfig()
	cli, srv := startPair(t, cfg, cfg, func(_ *Conn, st *Stream) {
		st.Pad = func(n int) int { return 100 }
		_ = st.WriteHeaders([]hpack.HeaderField{{Name: ":status", Value: "200"}}, false)
		for {
			p, end, err := st.ReadData()
			if err != nil {
				return
			}
			if end {
				if err := st.WriteData(p, true); err != nil {
					return
				}
				return
			}
			if err := st.WriteData(p, false); err != nil {
				return
			}
		}
	})

	st, err := cli.NewStream([]hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/x"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x7d}, 500)
	_ = st.WriteData(payload, false)
	_ = st.CloseSend()

	var got bytes.Buffer
	ended := false
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatalf("read: %v (client conn: %v, server conn: %v)", err, cli.ReadErr(), srv.ReadErr())
		}
		if p != nil {
			got.Write(p)
		}
		if end {
			ended = true
			break
		}
	}
	if !ended || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("padded echo mismatch: %d bytes, end=%v", got.Len(), ended)
	}
}

func TestFlowControlSmallWindow(t *testing.T) {
	clientCfg := DefaultConfig()
	clientCfg.Settings.InitialWindowSize = 16384
	clientCfg.StreamWindowChunk = 4096
	serverCfg := DefaultConfig()

	const total = 512 << 10
	cli, _ := startPair(t, serverCfg, clientCfg, func(_ *Conn, st *Stream) {
		_ = st.WriteHeaders([]hpack.HeaderField{{Name: ":status", Value: "200"}}, false)
		chunk := bytes.Repeat([]byte{0xa5}, 1024)
		sent := 0
		for sent < total {
			n := len(chunk)
			if sent+n > total {
				n = total - sent
			}
			if err := st.WriteData(chunk[:n], false); err != nil {
				return
			}
			sent += n
		}
		_ = st.CloseSend()
	})

	st, err := cli.NewStream([]hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/big"}}, true)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			buf.Write(p)
		}
		if end {
			break
		}
	}
	if buf.Len() != total {
		t.Fatalf("received %d bytes, want %d", buf.Len(), total)
	}
}

func TestResetPropagates(t *testing.T) {
	cfg := DefaultConfig()
	cli, _ := startPair(t, cfg, cfg, func(_ *Conn, st *Stream) {
		_ = st.WriteHeaders([]hpack.HeaderField{{Name: ":status", Value: "200"}}, false)
		// Block reading until reset.
		_, _, _ = st.ReadData()
	})

	st, err := cli.NewStream([]hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/x"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the handler reach ReadData
	if err := st.Reset(http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReadData(); !errors.Is(err, ErrReset) && !errors.Is(err, ErrConnClosed) {
		t.Fatalf("want reset error, got %v", err)
	}
}

func TestServerServesFakeRequest(t *testing.T) {
	cfg := DefaultConfig()
	cli, _ := startPair(t, cfg, cfg, func(_ *Conn, st *Stream) {
		var path string
		for _, h := range st.Headers() {
			if h.Name == ":path" {
				path = h.Value
			}
		}
		if path != "/index.m3u8" {
			_ = st.WriteHeaders([]hpack.HeaderField{{Name: ":status", Value: "404"}}, true)
			return
		}
		body := []byte("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n")
		_ = st.WriteHeaders([]hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/vnd.apple.mpegurl"},
			{Name: "content-length", Value: itoa(len(body))},
		}, false)
		_ = st.WriteData(body, true)
	})

	st, err := cli.NewStream([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "video.example.com"},
		{Name: ":path", Value: "/index.m3u8"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for {
		p, end, err := st.ReadData()
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			body = append(body, p...)
		}
		if end {
			break
		}
	}
	if !bytes.HasPrefix(body, []byte("#EXTM3U")) {
		t.Fatalf("bad manifest body: %q", body)
	}
	var status string
	for _, h := range st.Headers() {
		if h.Name == ":status" {
			status = h.Value
		}
	}
	if status != "200" {
		t.Fatalf("bad status: %q", status)
	}
}

func TestConnErrorPath(t *testing.T) {
	cfg := DefaultConfig()
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		c, err := ServerConn(serverSide, cfg, nil)
		if err == nil {
			// Close underneath to simulate a dead peer.
			time.Sleep(50 * time.Millisecond)
			_ = c.nc.Close()
		}
		done <- err
	}()
	cli, err := ClientConn(clientSide, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Let the connection die.
	select {
	case <-time.After(testTimeout):
		t.Fatal("connection did not fail")
	case <-cli.closeNotify:
	}
	<-done
	if err := cli.sendFrame(func() error { return nil }); err == nil {
		t.Fatal("send on closed conn succeeded")
	}
}

func TestPrefaceRejected(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		c, err := ServerConn(serverSide, DefaultConfig(), nil)
		if err == nil {
			c.failConn(io.EOF)
		}
		done <- err
	}()
	// Send a bogus preface (≥ 24 bytes so ReadFull completes).
	_, _ = clientSide.Write([]byte("GET / HTTP/1.1\r\n\r\n0123456789"))
	if err := <-done; err == nil {
		t.Fatal("bogus preface accepted")
	}
	_ = clientSide.Close()
}

// TestWriterLoopExitsOnFailure guards against the writerLoop goroutine
// leaking per connection (it must terminate via failConn when the
// socket dies; a leak pins the whole Conn object graph forever).
func TestWriterLoopExitsOnFailure(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		serverSide, clientSide := net.Pipe()
		type res struct {
			c   *Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, err := ServerConn(serverSide, DefaultConfig(), nil)
			ch <- res{c, err}
		}()
		cc, err := ClientConn(clientSide, DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		// Kill one side: both writer loops must shut down.
		_ = serverSide.Close()
		select {
		case <-cc.Done():
		case <-time.After(testTimeout):
			t.Fatal("client conn did not observe failure")
		}
		select {
		case <-r.c.Done():
		case <-time.After(testTimeout):
			t.Fatal("server conn did not observe failure")
		}
	}
	// Give exited goroutines a moment to wind down, then compare.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: %d -> %d", baseline, runtime.NumGoroutine())
}

// TestCloseReadWakesReader guards the relay unblocking path: a reader
// blocked in ReadData must wake up with ErrReadClosed when CloseRead is
// called while the peer is idle.
func TestCloseReadWakesReader(t *testing.T) {
	cli, _ := startPair(t, DefaultConfig(), DefaultConfig(), nil)
	defer cli.GoAway()
	st, err := cli.NewStream([]hpack.HeaderField{{Name: ":method", Value: "GET"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := st.ReadData()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the reader block
	st.CloseRead()
	select {
	case err := <-done:
		if err != ErrReadClosed {
			t.Fatalf("expected ErrReadClosed, got %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("blocked ReadData not woken by CloseRead")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
