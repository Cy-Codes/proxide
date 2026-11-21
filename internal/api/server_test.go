package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxide/internal/bus"
	"proxide/internal/ca"
	"proxide/internal/clientreg"
	"proxide/internal/config"
	"proxide/internal/model"
	"proxide/internal/rewrite"
	"proxide/internal/tlsmitm"
)

func newTestAPIHandler(t *testing.T, cfg config.Config) (*Handler, *bus.RingStore, *bus.Bus, *tlsmitm.Manager) {
	t.Helper()
	auth, err := ca.LoadOrCreate(ca.Options{Dir: filepath.Join(t.TempDir(), "ca")})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	tlsMgr := tlsmitm.NewManager(tlsmitm.Options{Signer: auth})
	store := bus.NewRingStore(100, 1024*1024)
	evBus := bus.NewBus(16)
	t.Cleanup(evBus.Close)
	rewriter, err := rewrite.NewEngine(nil, nil)
	if err != nil {
		t.Fatalf("rewrite.NewEngine: %v", err)
	}
	reg := clientreg.NewRegistry(clientreg.Options{
		TagHeader:   cfg.ClientTagHeader,
		StripHeader: true,
		MACResolver: clientreg.NoopMACResolver{},
	})

	h := NewHandler(Options{
		Config:     cfg,
		Store:      store,
		Subscriber: evBus,
		Clients:    reg,
		TLSManager: tlsMgr,
		RuleStore:  rewriter,
		CAProvider: auth,
	})
	return h, store, evBus, tlsMgr
}

func TestStrictJSONValidationConflictAndAuth(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.APIToken = "secret-tok"
	h, _, _, _ := newTestAPIHandler(t, cfg)

	// Unauthenticated request rejected.
	unauthRec := httptest.NewRecorder()
	h.ServeHTTP(unauthRec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", unauthRec.Code)
	}

	// Unknown field rejected by DisallowUnknownFields().
	badReq := httptest.NewRequest(http.MethodPut, "/api/v1/clients/192.168.1.40", strings.NewReader(`{"friendly_name":"TV","typo_field":1}`))
	badReq.Header.Set("Authorization", "Bearer secret-tok")
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field expected 400, got %d body=%s", badRec.Code, badRec.Body.String())
	}

	// Trailing token rejected.
	trailReq := httptest.NewRequest(http.MethodPut, "/api/v1/clients/192.168.1.40", strings.NewReader(`{"friendly_name":"TV"}{"extra":1}`))
	trailReq.Header.Set("Authorization", "Bearer secret-tok")
	trailRec := httptest.NewRecorder()
	h.ServeHTTP(trailRec, trailReq)
	if trailRec.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON expected 400, got %d", trailRec.Code)
	}

	// Duplicate rule ID maps to 409 Conflict.
	dupBody := `{"rules":[{"id":"r1","name":"A","enabled":true,"action":"header_rewrite"},{"id":"r1","name":"B","enabled":true,"action":"header_rewrite"}]}`
	dupReq := httptest.NewRequest(http.MethodPut, "/api/v1/rules", bytes.NewBufferString(dupBody))
	dupReq.Header.Set("Authorization", "Bearer secret-tok")
	dupRec := httptest.NewRecorder()
	h.ServeHTTP(dupRec, dupReq)
	if dupRec.Code != http.StatusConflict {
		t.Fatalf("duplicate rule expected 409, got %d body=%s", dupRec.Code, dupRec.Body.String())
	}
}

func TestSSEEventStreamReceivesPublishedFlows(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	h, store, evBus, _ := newTestAPIHandler(t, cfg)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events/stream?client_tag=firetv", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected SSE headers: status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	br := bufio.NewReader(resp.Body)
	firstLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(firstLine, ": connected") {
		t.Fatalf("expected : connected banner, got %q err=%v", firstLine, err)
	}
	_, _ = br.ReadString('\n') // blank separator

	ev := model.CaptureEvent{
		ID:        "flow_sse_1",
		Timestamp: time.Now().UTC(),
		Client:    model.ClientIdentity{IP: netip.MustParseAddr("192.168.1.90"), Tag: "firetv"},
		Protocol:  model.ProtocolHTTPS,
		Request:   &model.HTTPRequestSnapshot{Method: "GET", Host: "api.example.com", URL: "https://api.example.com/v1"},
		Response:  &model.HTTPResponseSnapshot{Status: 200},
	}
	store.Append(ev)
	evBus.Publish(ev)

	var eventLine, dataLine string
	for range 4 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE event: %v", err)
		}
		if strings.HasPrefix(line, "event:") {
			eventLine = strings.TrimSpace(line)
		} else if strings.HasPrefix(line, "data:") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			break
		}
	}
	if eventLine != "event: flow" {
		t.Fatalf("got event line %q, want event: flow", eventLine)
	}
	var decoded model.CaptureEvent
	if err := json.Unmarshal([]byte(dataLine), &decoded); err != nil {
		t.Fatalf("decode SSE JSON: %v", err)
	}
	if decoded.ID != "flow_sse_1" || decoded.Client.Tag != "firetv" {
		t.Fatalf("unexpected decoded SSE event: %+v", decoded)
	}
}
