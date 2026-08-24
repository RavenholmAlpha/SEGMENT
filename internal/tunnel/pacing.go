package tunnel

import (
	"math/rand/v2"
	"time"
)

// PadLen returns a random h2 DATA pad length (0..255) with zero pad
// bytes inside the frame — matching real-browser padding, which varies
// only the *length* field. This decorrelates frame sizes from payload
// sizes at the h2 layer (design doc §6.2).
func PadLen(int) int { return rand.IntN(256) }

// Pacing shapes outbound media traffic so a tunnel stream looks like a
// video segment download (design doc §5.3 / §6.3): data is emitted in
// bursts, with a short randomized pause between bursts.
//
// Zero value disables pacing.
type Pacing struct {
	Enabled  bool
	Burst    int           // bytes emitted per burst
	MinPause time.Duration // pause lower bound between bursts
	MaxPause time.Duration // pause upper bound between bursts
}

// DefaultPacing returns the production-ready camouflage pacing.
func DefaultPacing() Pacing {
	return Pacing{
		Enabled:  true,
		Burst:    256 << 10, // 256 KB per burst
		MinPause: 2 * time.Millisecond,
		MaxPause: 8 * time.Millisecond,
	}
}

// PacedWriter wraps a writer with media-style pacing.
type PacedWriter struct {
	w   func([]byte) error // writes one chunk (already framed)
	cfg Pacing
	rem int // bytes left in the current burst
}

// NewPacedWriter builds a pacer over f. When pacing is disabled, the
// returned wrapper passes writes through untouched.
func NewPacedWriter(cfg Pacing, w func([]byte) error) *PacedWriter {
	return &PacedWriter{w: w, cfg: cfg, rem: cfg.Burst}
}

// Write paces a chunk write.
func (p *PacedWriter) Write(chunk []byte) error {
	if !p.cfg.Enabled || p.cfg.Burst <= 0 {
		return p.w(chunk)
	}
	if err := p.w(chunk); err != nil {
		return err
	}
	p.rem -= len(chunk)
	if p.rem <= 0 {
		p.rem = p.cfg.Burst
		// Defensive against inverted pacing config: an empty or
		// negative jitter range would panic in rand.Int64N.
		span := p.cfg.MaxPause - p.cfg.MinPause
		if span <= 0 {
			time.Sleep(p.cfg.MinPause)
			return nil
		}
		d := time.Duration(rand.Int64N(int64(span + 1)))
		time.Sleep(p.cfg.MinPause + d)
	}
	return nil
}
