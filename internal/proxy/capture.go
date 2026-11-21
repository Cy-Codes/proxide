package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// NewFlowID generates a time-sortable unique capture event identifier.
func NewFlowID(now time.Time) string {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("flow_%012x_%s", now.UTC().UnixMilli(), hex.EncodeToString(rnd[:]))
}

// ReadAndRestoreBody captures up to maxCapture bytes of r without loading unbounded payloads into memory.
func ReadAndRestoreBody(
	r io.ReadCloser,
	maxCapture int64,
	contentType string,
) (restored io.ReadCloser, preview string, b64 string, totalBytes int64, truncated bool, err error) {
	if r == nil {
		return nil, "", "", 0, false, nil
	}
	if maxCapture <= 0 {
		return r, "", "", 0, false, nil
	}

	prefix, err := io.ReadAll(io.LimitReader(r, maxCapture+1))
	if err != nil {
		_ = r.Close()
		return nil, "", "", 0, false, err
	}

	if int64(len(prefix)) <= maxCapture {
		_ = r.Close()
		restored = io.NopCloser(bytes.NewReader(prefix))
		preview, b64 = formatCapturedBody(prefix, contentType)
		return restored, preview, b64, int64(len(prefix)), false, nil
	}

	captured := prefix[:maxCapture]
	preview, b64 = formatCapturedBody(captured, contentType)
	// Stitch already-read bytes ahead of remaining stream so upstream receives the complete payload.
	restored = multiReadCloser{
		Reader: io.MultiReader(bytes.NewReader(prefix), r),
		Closer: r,
	}
	return restored, preview, b64, int64(len(prefix)), true, nil
}

type multiReadCloser struct {
	io.Reader
	io.Closer
}

// capturingReadCloser tees up to maxBytes of streamed reads into memory without delaying downstream writes.
type capturingReadCloser struct {
	inner     io.ReadCloser
	maxBytes  int64
	mu        sync.Mutex
	buf       bytes.Buffer
	totalRead int64
	truncated bool
}

func newCapturingReadCloser(inner io.ReadCloser, maxBytes int64) *capturingReadCloser {
	if inner == nil {
		inner = io.NopCloser(bytes.NewReader(nil))
	}
	return &capturingReadCloser{
		inner:    inner,
		maxBytes: maxBytes,
	}
}

func (c *capturingReadCloser) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.totalRead += int64(n)
		if c.maxBytes > 0 {
			remaining := c.maxBytes - int64(c.buf.Len())
			if remaining > 0 {
				take := min(int64(n), remaining)
				_, _ = c.buf.Write(p[:take])
				if int64(n) > remaining {
					c.truncated = true
				}
			} else {
				c.truncated = true
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *capturingReadCloser) Close() error {
	return c.inner.Close()
}

func (c *capturingReadCloser) Snapshot(contentType string) (preview string, b64 string, totalBytes int64, truncated bool) {
	c.mu.Lock()
	raw := bytes.Clone(c.buf.Bytes())
	totalBytes = c.totalRead
	truncated = c.truncated
	c.mu.Unlock()

	preview, b64 = formatCapturedBody(raw, contentType)
	return preview, b64, totalBytes, truncated
}

func formatCapturedBody(raw []byte, contentType string) (preview string, b64 string) {
	if len(raw) == 0 {
		return "", ""
	}
	b64 = base64.StdEncoding.EncodeToString(raw)
	if isTextualPayload(raw, contentType) {
		return string(raw), b64
	}
	return "", b64
}

func isTextualPayload(raw []byte, contentType string) bool {
	if !utf8.Valid(raw) {
		return false
	}
	lower := strings.ToLower(contentType)
	if strings.HasPrefix(lower, "text/") ||
		strings.Contains(lower, "json") ||
		strings.Contains(lower, "xml") ||
		strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "x-www-form-urlencoded") {
		return true
	}
	// Heuristic check when Content-Type is omitted: reject NUL bytes.
	return !bytes.ContainsRune(raw, 0)
}
