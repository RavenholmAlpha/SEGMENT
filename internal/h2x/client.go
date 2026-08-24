package h2x

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

// NewStream opens a client-initiated stream with the given request
// headers. When endStream is true, no request body follows (GET-like);
// tunnel streams pass false so DATA frames can carry Segment frames.
func (c *Conn) NewStream(hf []hpack.HeaderField, endStream bool) (*Stream, error) {
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = ErrConnClosed
		}
		return nil, err
	}
	if int64(c.nextStreamID) > (1<<31)-1 {
		c.mu.Unlock()
		return nil, errors.New("h2x: stream id space exhausted")
	}
	id := c.nextStreamID
	c.nextStreamID += 2
	st := newStream(c, id, c.remoteInitWin)
	c.streams[id] = st
	c.mu.Unlock()

	if err := c.writeHeaders(id, hf, endStream); err != nil {
		c.delStream(id)
		return nil, err
	}
	if endStream {
		st.setLocalEnd()
	}
	return st, nil
}
