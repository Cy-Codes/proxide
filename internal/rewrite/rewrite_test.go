package rewrite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"proxide/internal/model"
)

func TestOSRootResolverRejectsTraversal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "fixture.json"), []byte(`{"mock":true}`), 0o600); err != nil {
		t.Fatalf("write inside fixture: %v", err)
	}

	resolver := NewOSRootResolver(root)

	data, err := resolver.ReadLocalFile("fixture.json")
	if err != nil {
		t.Fatalf("expected valid fixture read, got: %v", err)
	}
	if string(data) != `{"mock":true}` {
		t.Fatalf("unexpected fixture body: %s", data)
	}

	for _, bad := range []string{"../secret.txt", "/etc/passwd", "..\\secret.txt"} {
		if _, err := resolver.ReadLocalFile(bad); !errors.Is(err, model.ErrPathEscapesRoot) {
			t.Fatalf("path %q expected ErrPathEscapesRoot, got: %v", bad, err)
		}
	}
}

func TestEngineHeaderAndBodyRewriteReconcilesContentLength(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "local.json"), []byte(`{"mapped":1}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	engine, err := NewEngine(NewOSRootResolver(root), []model.RewriteRule{
		{
			ID:            "r-hdr",
			Name:          "Inject debug header",
			Enabled:       true,
			Priority:      10,
			ClientTag:     "firetv",
			HostPattern:   "*.example.com",
			PathPrefix:    "/v1/",
			Action:        model.ActionHeaderRewrite,
			Target:        TargetRequest,
			SetHeaders:    map[string]string{"X-Debug": "1"},
			RemoveHeaders: []string{"X-Old"},
		},
		{
			ID:              "r-body",
			Name:            "Replace JSON value",
			Enabled:         true,
			Priority:        20,
			HostPattern:     "api.example.com",
			PathPrefix:      "/v1/",
			Action:          model.ActionBodyRewrite,
			Target:          TargetResponse,
			BodyReplaceFrom: "prod",
			BodyReplaceTo:   "staging-override",
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	client := model.ClientIdentity{
		IP:  netip.MustParseAddr("192.168.1.40"),
		Tag: "firetv",
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/config", nil)
	req.Header.Set("X-Old", "drop")

	reqRes, err := engine.OnRequest(context.Background(), req, client)
	if err != nil {
		t.Fatalf("OnRequest: %v", err)
	}
	if req.Header.Get("X-Debug") != "1" || req.Header.Get("X-Old") != "" {
		t.Fatalf("unexpected mutated request headers: %v", req.Header)
	}
	if len(reqRes.Applied) != 1 || reqRes.Applied[0].RuleID != "r-hdr" {
		t.Fatalf("unexpected applied manipulations: %+v", reqRes.Applied)
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Length": {"15"}, "Transfer-Encoding": {"chunked"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"env":"prod"}`))),
	}

	respApplied, err := engine.OnResponse(context.Background(), req, resp, client)
	if err != nil {
		t.Fatalf("OnResponse: %v", err)
	}
	if len(respApplied) != 1 || respApplied[0].RuleID != "r-body" {
		t.Fatalf("unexpected response manipulations: %+v", respApplied)
	}
	newBody, _ := io.ReadAll(resp.Body)
	want := `{"env":"staging-override"}`
	if string(newBody) != want {
		t.Fatalf("got body %q, want %q", newBody, want)
	}
	if resp.ContentLength != int64(len(want)) || resp.Header.Get("Content-Length") != strconv.Itoa(len(want)) {
		t.Fatalf("unexpected Content-Length: field=%d header=%q", resp.ContentLength, resp.Header.Get("Content-Length"))
	}
	if resp.Header.Get("Transfer-Encoding") != "" {
		t.Fatal("expected Transfer-Encoding to be deleted after body rewrite")
	}
}

func TestEngineMapLocalReturnsSyntheticResponse(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "playback.json"), []byte(`{"url":"http://127.0.0.1/local.m3u8"}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	engine, err := NewEngine(NewOSRootResolver(root), []model.RewriteRule{
		{
			ID:          "r-map",
			Name:        "Mock playback manifest",
			Enabled:     true,
			Priority:    1,
			HostPattern: "cdn.example.com",
			PathPrefix:  "/manifest",
			Action:      model.ActionMapLocal,
			LocalPath:   "playback.json",
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/manifest.json", nil)
	res, err := engine.OnRequest(context.Background(), req, model.ClientIdentity{IP: netip.MustParseAddr("192.168.1.50")})
	if err != nil {
		t.Fatalf("OnRequest: %v", err)
	}
	if res.LocalResponse == nil {
		t.Fatal("expected Map Local synthetic response")
	}
	body, _ := io.ReadAll(res.LocalResponse.Body)
	if string(body) != `{"url":"http://127.0.0.1/local.m3u8"}` {
		t.Fatalf("unexpected Map Local body: %s", body)
	}
}
