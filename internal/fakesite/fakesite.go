// Package fakesite serves the caddy-like fake video site: a real
// HLS/DASH API whose manifests, media segments and thumbnails are
// deterministically generated and cacheable, so the tunnel server is a
// functional video site to anyone without tunnel credentials.
//
// The site is reachable over both HTTP/2 (the tunnel fronting layer)
// and HTTP/1.1 (legacy clients, privacy-protecting proxies that
// downgrade ALPN) so that ordinary browsing sessions always succeed.
package fakesite

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	"segment/internal/h2x"
)

// Site configures the fake site's look.
type Site struct {
	Title          string
	SegmentSeconds int
	// SegmentSizeKB are the possible media segment sizes (KB).
	SegmentSizeKB []int
}

// DefaultSite returns a reasonable default configuration.
func DefaultSite() *Site {
	return &Site{
		Title:          "StreamHub Video",
		SegmentSeconds: 6,
		SegmentSizeKB:  []int{256, 512, 1024},
	}
}

var (
	hlsSegRe  = regexp.MustCompile(`^/videos/([^/]+)/(seg|chunk)-(\d+)\.(ts|m4s)$`)
	thumbRe   = regexp.MustCompile(`^/videos/([^/]+)/thumb-(\d+)\.jpg$`)
	indexRe   = regexp.MustCompile(`^/videos/([^/]+)/index\.m3u8$`)
	dashRe    = regexp.MustCompile(`^/videos/([^/]+)/manifest\.mpd$`)
	previewRe = regexp.MustCompile(`^/videos/([^/]+)/preview\.(mp4|webm)$`)
)

// Content resolves a request path into the fake site's response.
func (s *Site) Content(path string) (status int, contentType string, body []byte, acceptRanges bool) {
	path = strings.SplitN(path, "?", 2)[0]
	switch {
	case path == "/" || path == "/index.html":
		return 200, "text/html; charset=utf-8", pageHTML(s.Title), false
	case path == "/api/v1/config":
		return 200, "application/json", configJSON(s), false
	case indexRe.MatchString(path):
		id := indexRe.FindStringSubmatch(path)[1]
		return 200, "application/vnd.apple.mpegurl", s.manifestHLS(id), false
	case dashRe.MatchString(path):
		id := dashRe.FindStringSubmatch(path)[1]
		return 200, "application/dash+xml", s.manifestDASH(id), false
	case hlsSegRe.MatchString(path):
		m := hlsSegRe.FindStringSubmatch(path)
		seq, _ := strconv.Atoi(m[3])
		ext := m[4]
		ct := "video/mp2t"
		if ext == "m4s" {
			ct = "video/mp4"
		}
		return 200, ct, mediaBytes(m[1], seq, s.pickSize(m[1], seq)), true
	case previewRe.MatchString(path):
		m := previewRe.FindStringSubmatch(path)
		ct := "video/mp4"
		if m[2] == "webm" {
			ct = "video/webm"
		}
		return 200, ct, mediaBytes(m[1], 0, 128<<10), true
	case thumbRe.MatchString(path):
		m := thumbRe.FindStringSubmatch(path)
		n, _ := strconv.Atoi(m[2])
		return 200, "image/jpeg", thumbBytes(m[1], n), false
	default:
		return 404, "text/html; charset=utf-8", notFoundHTML(s.Title), false
	}
}

// Serve answers one h2 stream as the fake site would. Runs on its own
// goroutine per stream; a panic must degrade just this stream, never
// the whole (unauthenticated-facing) server process.
func (s *Site) Serve(st *h2x.Stream) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("fakesite: recovered from panic serving h2 stream: %v", r)
			_ = st.Reset(0x2) // ErrCodeStreamClosed
		}
	}()
	path := ""
	for _, h := range st.Headers() {
		if h.Name == ":path" {
			path = h.Value
		}
	}
	status, ct, body, ranges := s.Content(path)
	if ranges {
		for _, h := range st.Headers() {
			if h.Name == "range" {
				if m := regexp.MustCompile(`bytes=(\d+)-`).FindStringSubmatch(h.Value); m != nil {
					if start, _ := strconv.Atoi(m[1]); start > 0 && start < len(body) {
						body = body[start:]
					}
				}
			}
		}
	}
	hdrs := []hpack.HeaderField{
		{Name: ":status", Value: strconv.Itoa(status)},
		{Name: "content-type", Value: ct},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
		{Name: "cache-control", Value: "public, max-age=300"},
		{Name: "etag", Value: `"` + etag(body) + `"`},
	}
	if ranges {
		hdrs = append(hdrs, hpack.HeaderField{Name: "accept-ranges", Value: "bytes"})
	}
	if err := st.WriteHeaders(hdrs, false); err != nil {
		return
	}
	if err := writeAll(st, body); err != nil {
		return
	}
	_ = st.CloseSend()
}

// ServeHTTP11 serves the fake site over HTTP/1.1 (legacy ALPN). It
// reads requests in a keep-alive loop and answers from Content().
// All reads are bounded: an endless or header-flooded request must not
// be able to grow server memory (unauthenticated path).
func (s *Site) ServeHTTP11(c net.Conn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("fakesite: recovered from panic serving http/1.1: %v", r)
		}
	}()
	br := bufio.NewReader(c)
	for {
		line, err := readLimitedLine(br, 8<<10)
		if err != nil {
			return
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return
		}
		method, target := parts[0], parts[1]
		// A real h2 client that failed ALPN negotiation speaks the h2
		// preface here; answer its request-line anyway would deadlock
		// (it waits for a SETTINGS frame we never send), so drop it.
		if method == "PRI" && strings.HasPrefix(target, "* HTTP/2.0") {
			return
		}
		path := strings.SplitN(target, "?", 2)[0]
		// Consume headers (incl. Content-Length body for POST), with
		// per-line and total caps.
		keepAlive := true
		cl := 0
		for n := 0; n < 100; n++ {
			h, err := readLimitedLine(br, 4<<10)
			if err != nil {
				return
			}
			if h == "\r\n" || h == "\n" {
				break
			}
			if n == 99 {
				return // header flood: drop the connection
			}
			hv := strings.ToLower(h)
			switch {
			case strings.HasPrefix(hv, "connection:"):
				keepAlive = !strings.Contains(strings.ToLower(h), "close")
			case strings.HasPrefix(hv, "content-length:"):
				cl, _ = strconv.Atoi(strings.TrimSpace(h[len("content-length:"):]))
				if cl < 0 || cl > 1<<20 {
					cl = 0 // absurd length: refuse to drain
				}
			}
		}
		if method == "POST" && cl > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
				return
			}
		}
		status, ct, body, _ := s.Content(path)
		reason := statusText(status)
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n", status, reason)
		fmt.Fprintf(c, "Content-Type: %s\r\nContent-Length: %d\r\n", ct, len(body))
		fmt.Fprintf(c, "Cache-Control: public, max-age=300\r\nETag: %q\r\n", etag(body))
		if !keepAlive {
			fmt.Fprint(c, "Connection: close\r\n")
		}
		fmt.Fprint(c, "\r\n")
		if _, err := c.Write(body); err != nil {
			return
		}
		if !keepAlive {
			return
		}
	}
}

// readLimitedLine reads one line while bounding how much input can be
// buffered on behalf of a single request line (an unbounded ReadString
// lets a peer grow memory by sending a huge no-newline blob).
func readLimitedLine(br *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		frag, err := br.ReadSlice('\n')
		b = append(b, frag...)
		if len(b) > max {
			return "", errors.New("fakesite: line too long")
		}
		if err != bufio.ErrBufferFull {
			return string(b), err
		}
	}
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 404:
		return "Not Found"
	default:
		return "OK"
	}
}

// writeAll streams body in h2-frame-sized chunks.
func writeAll(st *h2x.Stream, body []byte) error {
	const chunk = 16000
	for len(body) > 0 {
		n := len(body)
		if n > chunk {
			n = chunk
		}
		if err := st.WriteData(body[:n], false); err != nil {
			return err
		}
		body = body[n:]
	}
	return nil
}

func (s *Site) manifestHLS(id string) []byte {
	var b strings.Builder
	b.WriteString("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:")
	b.WriteString(strconv.Itoa(s.SegmentSeconds))
	b.WriteString("\n#EXT-X-MEDIA-SEQUENCE:0\n")
	const segs = 60
	for i := 0; i < segs; i++ {
		b.WriteString("#EXTINF:")
		b.WriteString(strconv.Itoa(s.SegmentSeconds))
		b.WriteString(",\n/videos/")
		b.WriteString(id)
		b.WriteString("/seg-")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(".ts\n")
	}
	b.WriteString("#EXT-X-ENDLIST\n")
	return []byte(b.String())
}

func (s *Site) manifestDASH(id string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" profiles="urn:mpeg:dash:profile:isoff-live:2011" type="static" mediaPresentationDuration="PT360S" minBufferTime="PT2S">` + "\n")
	b.WriteString(`<Period><AdaptationSet mimeType="video/mp4" segmentAlignment="true"><SegmentTemplate timescale="1" duration="`)
	b.WriteString(strconv.Itoa(s.SegmentSeconds))
	b.WriteString(`" media="/videos/` + id + `/chunk-$Number$.m4s" startNumber="1"/><Representation id="a" bandwidth="4000000" width="1920" height="1080"/></AdaptationSet></Period></MPD>` + "\n")
	return []byte(b.String())
}

func (s *Site) pickSize(id string, seq int) int {
	h := sha256.Sum256([]byte(id + "#" + strconv.Itoa(seq)))
	kl := s.SegmentSizeKB
	if len(kl) == 0 || kl[0] <= 0 {
		// Defensive: an empty or negative size list would divide by
		// zero or panic in make (an unauthenticated request must never
		// be able to crash the server). Fall back to a fixed size.
		return 1024 << 10
	}
	// Only positive entries participate; pickSize stays in-bounds and
	// positive regardless of config contents. Clamp to the largest
	// plausible segment so a wild config value cannot trigger an
	// oversized allocation on the request path.
	n := int(h[0]) % len(kl)
	if kl[n] <= 0 || kl[n] > 64<<10 {
		return 1024 << 10
	}
	return kl[n] << 10
}

// mediaBytes deterministically generates a media segment of the given
// size from (id, seq).
func mediaBytes(id string, seq int, size int) []byte {
	buf := make([]byte, size)
	seed := sha256.Sum256([]byte(id + "|" + strconv.Itoa(seq)))
	fill(buf, seed[:])
	return buf
}

// fill spreads a key stream over buf using a simple counter-mode hash.
func fill(buf []byte, key []byte) {
	var counter [8]byte
	var i int
	for i < len(buf) {
		h := sha256.Sum256(append(append([]byte(nil), key...), counter[:]...))
		c := append([]byte(nil), h[:]...)
		n := copy(buf[i:], c)
		i += n
		for j := 7; j >= 0; j-- {
			counter[j]++
			if counter[j] != 0 {
				break
			}
		}
	}
}

func thumbBytes(id string, n int) []byte {
	// Deterministic pseudo-JPEG-ish noise; small and cacheable.
	buf := make([]byte, 32<<10)
	seed := sha256.Sum256([]byte("thumb|" + id + "|" + strconv.Itoa(n)))
	fill(buf, seed[:])
	// Prepend a JPEG SOI marker so it looks like a real image.
	buf[0], buf[1] = 0xFF, 0xD8
	return buf
}

func pageHTML(title string) []byte {
	return []byte(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>` + title + `</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8;margin:0}
header{padding:18px 28px;background:#161a22;border-bottom:1px solid #262c38}
main{padding:24px 28px}.v{display:inline-block;margin:8px;border-radius:8px;overflow:hidden;background:#161a22}
.v img{width:220px;height:124px;display:block}</style></head>
<body><header><strong>` + title + `</strong></header><main>
<h2>Featured</h2><div>
<a class="v" href="/videos/alpha/index.m3u8"><img src="/videos/alpha/thumb-1.jpg" alt=""></a>
<a class="v" href="/videos/beta/index.m3u8"><img src="/videos/beta/thumb-1.jpg" alt=""></a>
<a class="v" href="/videos/gamma/index.m3u8"><img src="/videos/gamma/thumb-1.jpg" alt=""></a>
<a class="v" href="/videos/delta/index.m3u8"><img src="/videos/delta/thumb-1.jpg" alt=""></a>
</div></main></body></html>`)
}

func configJSON(s *Site) []byte {
	return []byte(`{"player":{"autoplay":false,"preload":"auto","enableP2P":false},` +
		`"streams":{"hls":true,"dash":true},"segmentSeconds":` + strconv.Itoa(s.SegmentSeconds) + `}`)
}

func notFoundHTML(title string) []byte {
	return []byte(`<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p><a href="/">` +
		title + `</a></p></body></html>`)
}

func etag(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:12])
}
