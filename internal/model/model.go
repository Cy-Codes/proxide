package model

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"time"
)

// DevicePlatform represents a classified target device or client runtime.
type DevicePlatform string

const (
	PlatformFireTV        DevicePlatform = "fire_tv"
	PlatformAndroidTV     DevicePlatform = "android_tv"
	PlatformAndroid       DevicePlatform = "android"
	PlatformIOS           DevicePlatform = "ios"
	PlatformTVOS          DevicePlatform = "tvos"
	PlatformCLIController DevicePlatform = "cli_controller"
	PlatformDesktop       DevicePlatform = "desktop"
	PlatformUnknown       DevicePlatform = "unknown"
)

// FlowProtocol identifies the wire transport or higher-level stream type of a captured flow.
type FlowProtocol string

const (
	ProtocolHTTP   FlowProtocol = "http"
	ProtocolHTTPS  FlowProtocol = "https"
	ProtocolTunnel FlowProtocol = "tunnel"
	ProtocolWS     FlowProtocol = "ws"
	ProtocolWSS    FlowProtocol = "wss"
	ProtocolSSE    FlowProtocol = "sse"
)

// RuleAction enumerates supported traffic manipulation actions.
type RuleAction string

const (
	ActionMapLocal      RuleAction = "map_local"
	ActionHeaderRewrite RuleAction = "header_rewrite"
	ActionBodyRewrite   RuleAction = "body_rewrite"
)

// ErrorCode enumerates machine-readable API error categories.
type ErrorCode string

const (
	ErrCodeValidation       ErrorCode = "validation_error"
	ErrCodeNotFound         ErrorCode = "not_found"
	ErrCodeConflict         ErrorCode = "conflict"
	ErrCodePayloadTooLarge  ErrorCode = "payload_too_large"
	ErrCodeMethodNotAllowed ErrorCode = "method_not_allowed"
	ErrCodeUnauthorized     ErrorCode = "unauthorized"
	ErrCodeInternal         ErrorCode = "internal_error"
)

// Sentinel errors shared across packages for errors.Is matching.
var (
	ErrCertPinned      = errors.New("client likely rejected MITM certificate (pinning suspected)")
	ErrRuleConflict    = errors.New("rewrite rule conflict")
	ErrPathEscapesRoot = errors.New("map-local path escapes configured root directory")
	ErrFlowNotFound    = errors.New("captured flow not found")
	ErrInvalidConfig   = errors.New("invalid configuration")
	ErrInvalidLeafTTL  = errors.New("leaf certificate TTL exceeds policy bounds")
)

// ClientIdentity identifies a normalized LAN device or tagged local controller.
type ClientIdentity struct {
	IP           netip.Addr     `json:"ip"`
	Tag          string         `json:"tag,omitempty"`
	FriendlyName string         `json:"friendly_name,omitempty"`
	MAC          string         `json:"mac,omitempty"`
	Platform     DevicePlatform `json:"platform"`
}

// ClientRecord aggregates activity metadata for a tracked client.
type ClientRecord struct {
	ClientIdentity
	FlowCount uint64    `json:"flow_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HTTPRequestSnapshot captures an immutable snapshot of an HTTP request.
type HTTPRequestSnapshot struct {
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Host          string              `json:"host"`
	Path          string              `json:"path"`
	Headers       map[string][]string `json:"headers"`
	BodyPreview   string              `json:"body_preview,omitempty"`
	BodyBase64    string              `json:"body_base64,omitempty"`
	BodyBytes     int64               `json:"body_bytes"`
	BodyTruncated bool                `json:"body_truncated"`
}

// Clone returns a deep copy of the request snapshot.
func (s *HTTPRequestSnapshot) Clone() *HTTPRequestSnapshot {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Headers = CloneHeaders(s.Headers)
	return &cp
}

// HTTPResponseSnapshot captures an immutable snapshot of an HTTP response.
type HTTPResponseSnapshot struct {
	Status        int                 `json:"status"`
	StatusText    string              `json:"status_text"`
	Headers       map[string][]string `json:"headers"`
	BodyPreview   string              `json:"body_preview,omitempty"`
	BodyBase64    string              `json:"body_base64,omitempty"`
	BodyBytes     int64               `json:"body_bytes"`
	BodyTruncated bool                `json:"body_truncated"`
}

// Clone returns a deep copy of the response snapshot.
func (s *HTTPResponseSnapshot) Clone() *HTTPResponseSnapshot {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Headers = CloneHeaders(s.Headers)
	return &cp
}

// StreamFrame captures an individual WebSocket or SSE frame inside a flow.
type StreamFrame struct {
	Sequence       uint64    `json:"sequence"`
	Direction      string    `json:"direction"`
	Opcode         string    `json:"opcode"`
	PayloadPreview string    `json:"payload_preview,omitempty"`
	Bytes          int64     `json:"bytes"`
	Timestamp      time.Time `json:"timestamp"`
}

// FlowTiming records latency phases in milliseconds for a single flow.
type FlowTiming struct {
	DNSMs          int64 `json:"dns_ms"`
	TCPConnectMs   int64 `json:"tcp_connect_ms"`
	TLSHandshakeMs int64 `json:"tls_handshake_ms"`
	TTFBMs         int64 `json:"ttfb_ms"`
	TotalMs        int64 `json:"total_ms"`
}

// TLSInfo captures TLS metadata and passthrough/pin diagnostics for a flow.
type TLSInfo struct {
	SNI            string `json:"sni"`
	ALPN           string `json:"alpn,omitempty"`
	CipherSuite    string `json:"cipher_suite,omitempty"`
	LeafSerial     string `json:"leaf_serial,omitempty"`
	Passthrough    bool   `json:"passthrough"`
	PinSuspected   bool   `json:"pin_suspected"`
	HandshakeError string `json:"handshake_error,omitempty"`
}

// Clone returns a copy of TLSInfo.
func (t *TLSInfo) Clone() *TLSInfo {
	if t == nil {
		return nil
	}
	cp := *t
	return &cp
}

// AppliedManipulation records a manipulation rule executed on a flow.
type AppliedManipulation struct {
	RuleID   string     `json:"rule_id"`
	RuleName string     `json:"rule_name"`
	Action   RuleAction `json:"action"`
	Target   string     `json:"target"`
}

// RewriteRule defines a deterministic traffic matching and manipulation rule.
type RewriteRule struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	Priority        int               `json:"priority"`
	ClientIP        string            `json:"client_ip,omitempty"`
	ClientTag       string            `json:"client_tag,omitempty"`
	Method          string            `json:"method,omitempty"`
	HostPattern     string            `json:"host_pattern,omitempty"`
	PathPrefix      string            `json:"path_prefix,omitempty"`
	Action          RuleAction        `json:"action"`
	Target          string            `json:"target,omitempty"`
	LocalPath       string            `json:"local_path,omitempty"`
	SetHeaders      map[string]string `json:"set_headers,omitempty"`
	RemoveHeaders   []string          `json:"remove_headers,omitempty"`
	BodyReplaceFrom string            `json:"body_replace_from,omitempty"`
	BodyReplaceTo   string            `json:"body_replace_to,omitempty"`
}

// Clone returns a deep copy of the rewrite rule.
func (r RewriteRule) Clone() RewriteRule {
	cp := r
	if r.SetHeaders != nil {
		cp.SetHeaders = maps.Clone(r.SetHeaders)
	}
	if r.RemoveHeaders != nil {
		cp.RemoveHeaders = slices.Clone(r.RemoveHeaders)
	}
	return cp
}

// CaptureEvent represents an immutable structured capture record streamed to inspectors.
type CaptureEvent struct {
	ID            string                `json:"id"`
	Timestamp     time.Time             `json:"timestamp"`
	Client        ClientIdentity        `json:"client"`
	Protocol      FlowProtocol          `json:"protocol"`
	Request       *HTTPRequestSnapshot  `json:"request,omitempty"`
	Response      *HTTPResponseSnapshot `json:"response,omitempty"`
	StreamFrames  []StreamFrame         `json:"stream_frames"`
	Timing        FlowTiming            `json:"timing"`
	TLS           *TLSInfo              `json:"tls,omitempty"`
	Manipulations []AppliedManipulation `json:"manipulations"`
	BytesUp       int64                 `json:"bytes_up"`
	BytesDown     int64                 `json:"bytes_down"`
	Error         string                `json:"error,omitempty"`
}

// Clone returns a deep copy of CaptureEvent with non-nil JSON slice fields.
func (e CaptureEvent) Clone() CaptureEvent {
	cp := e
	cp.Request = e.Request.Clone()
	cp.Response = e.Response.Clone()
	cp.TLS = e.TLS.Clone()
	if e.StreamFrames == nil {
		cp.StreamFrames = []StreamFrame{}
	} else {
		cp.StreamFrames = slices.Clone(e.StreamFrames)
	}
	if e.Manipulations == nil {
		cp.Manipulations = []AppliedManipulation{}
	} else {
		cp.Manipulations = slices.Clone(e.Manipulations)
	}
	return cp
}

// FieldViolation describes a single validation error on an API request payload.
type FieldViolation struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ApiError represents the canonical JSON error envelope returned by the Control API.
type ApiError struct {
	Code        ErrorCode        `json:"code"`
	Message     string           `json:"message"`
	TraceID     string           `json:"trace_id,omitempty"`
	FieldErrors []FieldViolation `json:"field_errors,omitempty"`
}

// Error implements the error interface.
func (e ApiError) Error() string {
	return e.Message
}

// CloneHeaders deep-copies a multi-value header map into a newly allocated non-nil map.
func CloneHeaders(src map[string][]string) map[string][]string {
	dst := make(map[string][]string, len(src))
	for key, vals := range src {
		dst[key] = slices.Clone(vals)
	}
	return dst
}
