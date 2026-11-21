package rewrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"proxide/internal/config"
	"proxide/internal/model"
)

const (
	TargetRequest  = "request"
	TargetResponse = "response"
)

// RequestResult reports either a synthetic local response (e.g. Map Local) or mutated request manipulations.
type RequestResult struct {
	LocalResponse *http.Response
	Applied       []model.AppliedManipulation
}

// Interceptor defines the manipulation hook boundary invoked by the proxy around upstream round trips.
type Interceptor interface {
	OnRequest(ctx context.Context, req *http.Request, client model.ClientIdentity) (RequestResult, error)
	OnResponse(ctx context.Context, req *http.Request, resp *http.Response, client model.ClientIdentity) ([]model.AppliedManipulation, error)
}

// RuleStore exposes immutable rule snapshots and atomic replacement for control APIs.
type RuleStore interface {
	ListRules() []model.RewriteRule
	ReplaceRules(rules []model.RewriteRule) error
}

// LocalFileResolver loads static fixture payloads safely within a jailed root directory.
type LocalFileResolver interface {
	ReadLocalFile(relPath string) ([]byte, error)
}

// OSRootResolver serves Map Local files strictly beneath a configured root using Go's os.Root jail.
type OSRootResolver struct {
	rootDir string
}

// NewOSRootResolver constructs a root-jailed file resolver for Map Local fixtures.
func NewOSRootResolver(rootDir string) *OSRootResolver {
	return &OSRootResolver{rootDir: strings.TrimSpace(rootDir)}
}

// ReadLocalFile opens relPath strictly inside rootDir, rejecting absolute paths and traversal escapes.
func (r *OSRootResolver) ReadLocalFile(relPath string) ([]byte, error) {
	if r.rootDir == "" {
		return nil, fmt.Errorf("%w: map-local root directory is not configured", model.ErrPathEscapesRoot)
	}
	cleaned := filepath.Clean(relPath)
	if cleaned == "." || filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return nil, fmt.Errorf("%w: %q", model.ErrPathEscapesRoot, relPath)
	}

	root, err := os.OpenRoot(r.rootDir)
	if err != nil {
		return nil, fmt.Errorf("open map-local root %q: %w", r.rootDir, err)
	}
	defer root.Close()

	f, err := root.Open(filepath.ToSlash(cleaned))
	if err != nil {
		if errors.Is(err, os.ErrInvalid) || strings.Contains(strings.ToLower(err.Error()), "escapes") {
			return nil, fmt.Errorf("%w: %q: %w", model.ErrPathEscapesRoot, relPath, err)
		}
		return nil, fmt.Errorf("open map-local fixture %q: %w", relPath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, config.DefaultMaxBodyCaptureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read map-local fixture %q: %w", relPath, err)
	}
	if int64(len(data)) > config.DefaultMaxBodyCaptureBytes {
		return nil, fmt.Errorf("map-local fixture %q exceeds %d byte limit", relPath, config.DefaultMaxBodyCaptureBytes)
	}
	return data, nil
}

// NoopInterceptor implements Interceptor without modifying traffic.
type NoopInterceptor struct{}

// OnRequest returns an empty RequestResult.
func (NoopInterceptor) OnRequest(context.Context, *http.Request, model.ClientIdentity) (RequestResult, error) {
	return RequestResult{}, nil
}

// OnResponse returns nil manipulations.
func (NoopInterceptor) OnResponse(context.Context, *http.Request, *http.Response, model.ClientIdentity) ([]model.AppliedManipulation, error) {
	return nil, nil
}

type ruleSnapshot struct {
	rules []model.RewriteRule
}

// Engine evaluates immutable RewriteRule snapshots on request and response paths.
type Engine struct {
	localResolver LocalFileResolver
	snapshot      atomic.Pointer[ruleSnapshot]
}

// NewEngine creates a rule manipulation Engine.
func NewEngine(localResolver LocalFileResolver, initial []model.RewriteRule) (*Engine, error) {
	e := &Engine{localResolver: localResolver}
	if err := e.ReplaceRules(initial); err != nil {
		return nil, err
	}
	return e, nil
}

// ListRules returns a defensive clone of active rules in evaluation order.
func (e *Engine) ListRules() []model.RewriteRule {
	snap := e.snapshot.Load()
	if snap == nil || len(snap.rules) == 0 {
		return []model.RewriteRule{}
	}
	out := make([]model.RewriteRule, len(snap.rules))
	for i, r := range snap.rules {
		out[i] = r.Clone()
	}
	return out
}

// ReplaceRules validates, clones, sorts, and atomically swaps the active rule set.
func (e *Engine) ReplaceRules(rules []model.RewriteRule) error {
	seen := make(map[string]struct{}, len(rules))
	cloned := make([]model.RewriteRule, 0, len(rules))
	for _, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("%w: rewrite rule ID must not be empty", model.ErrInvalidConfig)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("%w: duplicate rule ID %q", model.ErrRuleConflict, r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.ClientIP != "" {
			if _, err := netip.ParseAddr(strings.TrimSpace(r.ClientIP)); err != nil {
				return fmt.Errorf("%w: rule %q invalid client_ip %q: %w", model.ErrInvalidConfig, r.ID, r.ClientIP, err)
			}
		}
		cloned = append(cloned, r.Clone())
	}

	slices.SortFunc(cloned, func(a, b model.RewriteRule) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		return strings.Compare(a.ID, b.ID)
	})

	e.snapshot.Store(&ruleSnapshot{rules: cloned})
	return nil
}

// OnRequest evaluates request-phase header/body rewrites and Map Local responses.
func (e *Engine) OnRequest(_ context.Context, req *http.Request, client model.ClientIdentity) (RequestResult, error) {
	snap := e.snapshot.Load()
	if snap == nil || len(snap.rules) == 0 || req == nil {
		return RequestResult{}, nil
	}

	host := stripHostPort(req.Host)
	path := req.URL.Path
	var applied []model.AppliedManipulation

	for _, rule := range snap.rules {
		if !MatchRule(rule, req.Method, host, path, client) {
			continue
		}
		target := strings.ToLower(strings.TrimSpace(rule.Target))
		switch rule.Action {
		case model.ActionMapLocal:
			if e.localResolver == nil {
				continue
			}
			body, err := e.localResolver.ReadLocalFile(rule.LocalPath)
			if err != nil {
				return RequestResult{}, err
			}
			hdr := make(http.Header)
			hdr.Set("Content-Type", detectContentType(rule.LocalPath, body))
			applyHeaderMutations(hdr, rule.SetHeaders, rule.RemoveHeaders)
			ReconcileBodyHeaders(hdr, len(body))

			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Status:        http.StatusText(http.StatusOK),
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        hdr,
				Body:          io.NopCloser(bytes.NewReader(body)),
				ContentLength: int64(len(body)),
				Request:       req,
			}
			applied = append(applied, model.AppliedManipulation{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Action:   rule.Action,
				Target:   TargetResponse,
			})
			return RequestResult{LocalResponse: resp, Applied: applied}, nil

		case model.ActionHeaderRewrite:
			if target == "" || target == TargetRequest {
				applyHeaderMutations(req.Header, rule.SetHeaders, rule.RemoveHeaders)
				applied = append(applied, model.AppliedManipulation{
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Action:   rule.Action,
					Target:   TargetRequest,
				})
			}

		case model.ActionBodyRewrite:
			if target == TargetRequest && rule.BodyReplaceFrom != "" && req.Body != nil {
				replaced, changed, err := replacePlaintextBody(req.Body, req.Header, rule.BodyReplaceFrom, rule.BodyReplaceTo)
				if err != nil {
					return RequestResult{}, err
				}
				if changed {
					req.Body = io.NopCloser(bytes.NewReader(replaced))
					req.ContentLength = ReconcileBodyHeaders(req.Header, len(replaced))
					applied = append(applied, model.AppliedManipulation{
						RuleID:   rule.ID,
						RuleName: rule.Name,
						Action:   rule.Action,
						Target:   TargetRequest,
					})
				}
			}
		}
	}

	return RequestResult{Applied: applied}, nil
}

// OnResponse evaluates response-phase header and body rewrites.
func (e *Engine) OnResponse(_ context.Context, req *http.Request, resp *http.Response, client model.ClientIdentity) ([]model.AppliedManipulation, error) {
	snap := e.snapshot.Load()
	if snap == nil || len(snap.rules) == 0 || req == nil || resp == nil {
		return nil, nil
	}

	host := stripHostPort(req.Host)
	path := req.URL.Path
	var applied []model.AppliedManipulation

	for _, rule := range snap.rules {
		if !MatchRule(rule, req.Method, host, path, client) {
			continue
		}
		target := strings.ToLower(strings.TrimSpace(rule.Target))
		switch rule.Action {
		case model.ActionHeaderRewrite:
			if target == "" || target == TargetResponse {
				applyHeaderMutations(resp.Header, rule.SetHeaders, rule.RemoveHeaders)
				applied = append(applied, model.AppliedManipulation{
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Action:   rule.Action,
					Target:   TargetResponse,
				})
			}
		case model.ActionBodyRewrite:
			if (target == "" || target == TargetResponse) && rule.BodyReplaceFrom != "" && resp.Body != nil {
				replaced, changed, err := replacePlaintextBody(resp.Body, resp.Header, rule.BodyReplaceFrom, rule.BodyReplaceTo)
				if err != nil {
					return applied, err
				}
				if changed {
					resp.Body = io.NopCloser(bytes.NewReader(replaced))
					resp.ContentLength = ReconcileBodyHeaders(resp.Header, len(replaced))
					applied = append(applied, model.AppliedManipulation{
						RuleID:   rule.ID,
						RuleName: rule.Name,
						Action:   rule.Action,
						Target:   TargetResponse,
					})
				}
			}
		}
	}
	return applied, nil
}

// MatchRule is a pure predicate testing whether a rule applies to the given request and client.
func MatchRule(rule model.RewriteRule, method, host, path string, client model.ClientIdentity) bool {
	if !rule.Enabled {
		return false
	}
	if rule.ClientIP != "" {
		wantIP, err := netip.ParseAddr(strings.TrimSpace(rule.ClientIP))
		if err != nil || wantIP.Unmap() != client.IP.Unmap() {
			return false
		}
	}
	if rule.ClientTag != "" && rule.ClientTag != client.Tag {
		return false
	}
	if rule.Method != "" && !strings.EqualFold(strings.TrimSpace(rule.Method), method) {
		return false
	}
	if rule.HostPattern != "" && !matchHost(rule.HostPattern, host) {
		return false
	}
	if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
		return false
	}
	return true
}

// ReconcileBodyHeaders sets exact Content-Length and strips stale Transfer-Encoding / Content-Encoding.
func ReconcileBodyHeaders(headers http.Header, bodyLen int) int64 {
	if headers == nil {
		return int64(bodyLen)
	}
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Encoding")
	headers.Set("Content-Length", strconv.Itoa(bodyLen))
	return int64(bodyLen)
}

func applyHeaderMutations(hdr http.Header, setHeaders map[string]string, removeHeaders []string) {
	if hdr == nil {
		return
	}
	for _, key := range removeHeaders {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			hdr.Del(trimmed)
		}
	}
	for key, val := range setHeaders {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			hdr.Set(trimmed, val)
		}
	}
}

func replacePlaintextBody(body io.ReadCloser, headers http.Header, from, to string) ([]byte, bool, error) {
	// Skip compressed payloads safely rather than corrupting binary gzip/br streams.
	if enc := strings.TrimSpace(headers.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, config.DefaultMaxBodyCaptureBytes+1))
	_ = body.Close()
	if err != nil {
		return nil, false, fmt.Errorf("read body for rewrite: %w", err)
	}
	if int64(len(raw)) > config.DefaultMaxBodyCaptureBytes {
		return raw, false, nil
	}
	if !bytes.Contains(raw, []byte(from)) {
		return raw, false, nil
	}
	updated := bytes.ReplaceAll(raw, []byte(from), []byte(to))
	return updated, true, nil
}

func matchHost(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if p == "" || h == "" {
		return false
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:]
		return strings.HasSuffix(h, suffix) && len(h) > len(suffix)
	}
	return p == h
}

func stripHostPort(raw string) string {
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return raw
}

func detectContentType(path string, body []byte) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json; charset=utf-8"
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	default:
		return http.DetectContentType(body)
	}
}
