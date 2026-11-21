package proxy

import (
	"maps"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
)

// RFC 9110 §7.6.1 hop-by-hop header names that proxies must not forward verbatim.
var standardHopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

var sensitiveHeaderNames = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"X-Api-Key":           {},
}

// StripHopByHopHeaders removes RFC 9110 hop-by-hop headers and any fields named in Connection.
func StripHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	var connListed []string
	for _, v := range h.Values("Connection") {
		for token := range strings.SplitSeq(v, ",") {
			if name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(token)); name != "" {
				connListed = append(connListed, name)
			}
		}
	}
	for name := range standardHopByHopHeaders {
		h.Del(name)
	}
	for _, name := range connListed {
		h.Del(name)
	}
}

// IsWebSocketUpgrade reports whether headers request an HTTP Upgrade to WebSocket.
func IsWebSocketUpgrade(h http.Header) bool {
	if h == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(h.Get("Upgrade")), "websocket") {
		return false
	}
	for _, v := range h.Values("Connection") {
		for token := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// HeaderToMap clones an http.Header into an immutable-friendly map[string][]string.
func HeaderToMap(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for key, vals := range h {
		out[key] = slices.Clone(vals)
	}
	return out
}

// CopyHeaders copies src headers into dst, cloning slice values.
func CopyHeaders(dst, src http.Header) {
	for key, vals := range src {
		dst[key] = slices.Clone(vals)
	}
}

// RedactSensitiveHeaders returns a copy of headers with credential/cookie values masked.
func RedactSensitiveHeaders(src map[string][]string) map[string][]string {
	out := maps.Clone(src)
	for key := range src {
		canon := textproto.CanonicalMIMEHeaderKey(key)
		if _, sensitive := sensitiveHeaderNames[canon]; sensitive {
			out[key] = []string{"[REDACTED]"}
		} else {
			out[key] = slices.Clone(src[key])
		}
	}
	return out
}
