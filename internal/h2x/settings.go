// Package h2x implements the Segment fronting layer: a minimal but
// spec-compliant HTTP/2 engine built directly on x/net/http2.Framer,
// used by both the client (browser-like behavior) and the server
// (caddy-like fake video site). Applications interact with streams at
// DATA-frame granularity, which maps 1:1 onto Segment inner frames and
// gives the disguise layer exact control over frame sizes and padding.
package h2x

import (
	"errors"
	"fmt"
	"time"
)

// Config tunes the h2 connection behavior.
type Config struct {
	// Settings are the SETTINGS we advertise (Chrome-like defaults).
	Settings Settings

	// MaxFrameSize caps the DATA frames we emit (h2 max is 16384 by
	// default; peers may advertise more, we never exceed this).
	MaxFrameSize uint32

	// Client behavior knobs.
	// SendConnWindowUpdate, when true, tops the connection window up to
	// ConnWindow after the settings exchange (large transfer head-room).
	SendConnWindowUpdate bool
	// ConnWindow is the connection-level receive window target in bytes
	// (we advertise it via an initial WINDOW_UPDATE and replenish in
	// chunks of ConnWindowChunk).
	ConnWindow        int64
	ConnWindowChunk   int64
	StreamWindowChunk int64

	// ReadTimeout/WriteTimeout guard stuck peers; zero disables.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DefaultConfig returns browser-like default settings.
func DefaultConfig() Config {
	return Config{
		Settings: BrowserSettings(),
		// Chrome does not raise MAX_FRAME_SIZE; 16384 is the default.
		MaxFrameSize:         16384,
		SendConnWindowUpdate: true,
		ConnWindow:           64 << 20,
		ConnWindowChunk:      1 << 20,
		StreamWindowChunk:    256 << 10,
	}
}

// Settings mirrors the h2 SETTINGS frame parameters we advertise.
type Settings struct {
	HeaderTableSize      uint32
	EnablePush           *bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

// BrowserSettings returns Chrome-1xx-like values (see docs/design.md §3.2).
func BrowserSettings() Settings {
	f := false
	return Settings{
		HeaderTableSize:      65536,
		EnablePush:           &f,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxHeaderListSize:    262144,
	}
}

// Standard settings defaults (RFC 9113 §6.5.2).
const (
	DefaultHeaderTableSize      = 4096
	DefaultInitialWindowSize    = 65535
	DefaultMaxFrameSize         = 16384
	DefaultMaxConcurrentStreams = 0xFFFFFFFF
)

var (
	ErrStreamClosed = errors.New("h2x: stream closed")
	ErrConnClosed   = errors.New("h2x: connection closed")
	ErrReset        = errors.New("h2x: stream reset")
	ErrFlowControl  = errors.New("h2x: flow control window exceeded")
)

func (s Settings) initialWindow() int64 { return int64(s.InitialWindowSize) }

func (s Settings) maxFrameSize() uint32 {
	if s.MaxFrameSize == 0 {
		return DefaultMaxFrameSize
	}
	return s.MaxFrameSize
}

func (s Settings) String() string {
	return fmt.Sprintf("h2-settings{headerTable=%d push=%v maxStreams=%d win=%d frame=%d headerList=%d}",
		s.HeaderTableSize, s.EnablePush, s.MaxConcurrentStreams, s.InitialWindowSize, s.MaxFrameSize, s.MaxHeaderListSize)
}
