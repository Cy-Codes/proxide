package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"proxide/internal/bus"
	"proxide/internal/ca"
	"proxide/internal/clientreg"
	"proxide/internal/config"
	"proxide/internal/model"
	"proxide/internal/portal"
	"proxide/internal/rewrite"
	"proxide/internal/tlsmitm"
)

func TestStripHopByHopHeadersAndConnectionTokens(t *testing.T) {
	t.Parallel()
	h := http.Header{
		"Connection":          {"keep-alive, X-Custom-Hop"},
		"X-Custom-Hop":        {"drop-me"},
		"Proxy-Authorization": {"Basic abc"},
		"Transfer-Encoding":   {"chunked"},
		"X-Keep-Header":       {"stay"},
	}
	StripHopByHopHeaders(h)
	if h.Get("Connection") != "" || h.Get("X-Custom-Hop") != "" || h.Get("Proxy-Authorization") != "" || h.Get("Transfer-Encoding") != "" {
		t.Fatalf("expected hop-by-hop headers to be stripped, remaining: %v", h)
	}
	if h.Get("X-Keep-Header") != "stay" {
		t.Fatalf("expected X-Keep-Header to remain, got %v", h)
	}
}

func FuzzStripHopByHopHeaders(f *testing.F) {
	f.Add("keep-alive, X-Foo", "bar")
	f.Add("upgrade, , teardown", "baz")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, connVal, customVal string) {
		h := http.Header{}
		h.Set("Connection", connVal)
		h.Set("X-Foo", customVal)
		h.Set("X-Safe", "ok")
		StripHopByHopHeaders(h)
		if h.Get("X-Safe") != "ok" {
			t.Fatal("StripHopByHopHeaders accidentally removed unrelated header")
		}
	})
}

func TestHTTPForwardProxyWireFidelityAndClientTagging(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://example.com/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		if got := r.Header.Get("X-Proxide-Client"); got != "" {
			t.Errorf("expected X-Proxide-Client to be stripped upstream, got %q", got)
		}
		var gzBuf bytes.Buffer
		zw := gzip.NewWriter(&gzBuf)
		_, _ = zw.Write([]byte(`{"wire":"gzip"}`))
		_ = zw.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	}))
	defer upstream.Close()

	store := bus.NewRingStore(100, 1024*1024)
	evBus := bus.NewBus(16)
	defer evBus.Close()

	cfg := config.Default()
	cfg.CADir = filepath.Join(t.TempDir(), "ca")
	proxyHandler := NewHandler(Options{
		Config: cfg,
		Clients: clientreg.NewRegistry(clientreg.Options{
			TagHeader:   cfg.ClientTagHeader,
			StripHeader: true,
			MACResolver: clientreg.NoopMACResolver{},
		}),
		Store:     store,
		Publisher: evBus,
	})
	defer proxyHandler.Close()

	proxySrv := httptest.NewServer(proxyHandler)
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			DisableCompression: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Verify 302 redirect is returned directly (not silently followed by proxy).
	redirReq, _ := http.NewRequest(http.MethodGet, upstream.URL+"/redirect", nil)
	redirReq.Header.Set("X-Proxide-Client", "controller-alpha")
	redirResp, err := client.Do(redirReq)
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}
	_ = redirResp.Body.Close()
	if redirResp.StatusCode != http.StatusFound || redirResp.Header.Get("Location") != "http://example.com/next" {
		t.Fatalf("expected raw 302 redirect, got status=%d loc=%q", redirResp.StatusCode, redirResp.Header.Get("Location"))
	}

	// 2. Verify gzip encoding passes through untouched without auto-decompression.
	gzReq, _ := http.NewRequest(http.MethodGet, upstream.URL+"/gzip", nil)
	gzReq.Header.Set("X-Proxide-Client", "controller-beta")
	gzResp, err := client.Do(gzReq)
	if err != nil {
		t.Fatalf("gzip request failed: %v", err)
	}
	rawGz, _ := io.ReadAll(gzResp.Body)
	_ = gzResp.Body.Close()
	if gzResp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip preserved, got %q", gzResp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(rawGz))
	if err != nil {
		t.Fatalf("expected valid gzip body, got err: %v", err)
	}
	plain, _ := io.ReadAll(zr)
	_ = zr.Close()
	if string(plain) != `{"wire":"gzip"}` {
		t.Fatalf("unexpected decoded payload: %s", plain)
	}

	flows := store.List(bus.FlowFilter{Limit: 10})
	if len(flows) != 2 {
		t.Fatalf("expected 2 captured flows, got %d", len(flows))
	}
	if flows[0].Client.Tag != "controller-beta" || flows[1].Client.Tag != "controller-alpha" {
		t.Fatalf("unexpected client tags on captured flows: %+v", flows)
	}
}

func TestConnectTunnelHalfCloseAndNoGoroutineLeak(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	// Echo server supporting TCP half-close: reads until EOF, then responds and closes.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write([]byte("echo:" + string(data)))
			}(conn)
		}
	}()

	store := bus.NewRingStore(100, 1024*1024)
	cfg := config.Default()
	proxyHandler := NewHandler(Options{
		Config: cfg,
		Clients: clientreg.NewRegistry(clientreg.Options{
			MACResolver: clientreg.NoopMACResolver{},
		}),
		Store: store,
	})
	defer proxyHandler.Close()

	proxySrv := httptest.NewServer(proxyHandler)
	defer proxySrv.Close()

	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")
	baseline := runtime.NumGoroutine()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	tcpConn := conn.(*net.TCPConn)

	target := ln.Addr().String()
	_, _ = tcpConn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))

	br := bufio.NewReader(tcpConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected CONNECT response: %q err=%v", statusLine, err)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}

	_, _ = tcpConn.Write([]byte("ping"))
	_ = tcpConn.CloseWrite()

	respData, err := io.ReadAll(br)
	_ = tcpConn.Close()
	if err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(respData) != "echo:ping" {
		t.Fatalf("got %q, want echo:ping", respData)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.List(bus.FlowFilter{Limit: 10})) == 1 && runtime.NumGoroutine() <= baseline+4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	flows := store.List(bus.FlowFilter{Limit: 10})
	if len(flows) != 1 || flows[0].Protocol != model.ProtocolTunnel {
		t.Fatalf("expected 1 tunnel flow, got %+v", flows)
	}
}

func TestEndToEndHTTPSMITMRewritePassthroughAndPortal(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Proxide-Client") != "" {
			t.Errorf("X-Proxide-Client leaked to upstream")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Injected") != "yes" {
			t.Errorf("expected rewrite engine to inject X-Injected header on %s", r.URL.Path)
		}
		reqBody, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"echo":` + `"` + string(reqBody) + `"` + `,"path":"` + r.URL.Path + `"}`))
	}))
	defer upstream.Close()

	caDir := filepath.Join(t.TempDir(), "ca")
	auth, err := ca.LoadOrCreate(ca.Options{Dir: caDir})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	tlsMgr := tlsmitm.NewManager(tlsmitm.Options{
		Signer:    auth,
		LeafTTL:   config.DefaultLeafCertTTL,
		CacheSize: 64,
	})
	rewriter, err := rewrite.NewEngine(nil, []model.RewriteRule{
		{
			ID:         "inject-hdr",
			Name:       "Inject X-Injected",
			Enabled:    true,
			Priority:   1,
			PathPrefix: "/api/",
			Action:     model.ActionHeaderRewrite,
			Target:     rewrite.TargetRequest,
			SetHeaders: map[string]string{"X-Injected": "yes"},
		},
	})
	if err != nil {
		t.Fatalf("rewrite.NewEngine: %v", err)
	}

	store := bus.NewRingStore(100, 1024*1024)
	evBus := bus.NewBus(32)
	defer evBus.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamCh, unsub := evBus.Subscribe(ctx, bus.EventFilter{})
	defer unsub()

	portalHandler := portal.NewHandler(portal.Options{
		CAProvider: auth,
		ProxyHost:  "127.0.0.1",
		ProxyPort:  "8080",
		PortalHost: "proxide.local",
		PortalPort: "8081",
	})

	cfg := config.Default()
	cfg.CADir = caDir
	cfg.InsecureUpstream = true // upstream httptest.NewTLSServer uses an ephemeral self-signed test cert

	proxyHandler := NewHandler(Options{
		Config: cfg,
		Clients: clientreg.NewRegistry(clientreg.Options{
			TagHeader:   cfg.ClientTagHeader,
			StripHeader: true,
			MACResolver: clientreg.NoopMACResolver{},
		}),
		TLSManager:    tlsMgr,
		Interceptor:   rewriter,
		PortalHandler: portalHandler,
		Store:         store,
		Publisher:     evBus,
	})
	defer proxyHandler.Close()

	proxySrv := httptest.NewServer(proxyHandler)
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)

	// Build a client trusting ONLY Proxide's local Root CA (never upstream's cert).
	mitmRoots := x509.NewCertPool()
	if !mitmRoots.AppendCertsFromPEM(auth.CertPEM()) {
		t.Fatal("failed to parse Proxide Root CA PEM")
	}
	mitmClient := &http.Client{
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				RootCAs: mitmRoots,
			},
		},
	}

	// 1. Two sequential keep-alive HTTPS requests over CONNECT MITM.
	for _, path := range []string{"/api/one", "/api/two"} {
		req, _ := http.NewRequest(http.MethodPost, upstream.URL+path, strings.NewReader("hello-"+path))
		req.Header.Set("User-Agent", "AppleTV14,1/18.1 tvOS/18.1")
		req.Header.Set("X-Proxide-Client", "tvos-runner")
		resp, err := mitmClient.Do(req)
		if err != nil {
			t.Fatalf("MITM request %s failed: %v", path, err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(bodyBytes), `"path":"`+path+`"`) {
			t.Fatalf("unexpected MITM body for %s: %s", path, bodyBytes)
		}
	}

	// Verify decrypted HTTPS events landed on Bus and Store with tvOS classification and rewrite record.
	var ev1, ev2 model.CaptureEvent
	select {
	case ev1 = <-streamCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first stream event")
	}
	select {
	case ev2 = <-streamCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second stream event")
	}
	for _, ev := range []model.CaptureEvent{ev1, ev2} {
		if ev.Protocol != model.ProtocolHTTPS {
			t.Fatalf("expected HTTPS protocol, got %s", ev.Protocol)
		}
		if ev.Client.Platform != model.PlatformTVOS || ev.Client.Tag != "tvos-runner" {
			t.Fatalf("unexpected client identity: %+v", ev.Client)
		}
		if ev.TLS == nil || ev.TLS.LeafSerial == "" || ev.TLS.Passthrough {
			t.Fatalf("unexpected TLS metadata: %+v", ev.TLS)
		}
		if len(ev.Manipulations) != 1 || ev.Manipulations[0].RuleID != "inject-hdr" {
			t.Fatalf("expected rewrite manipulation recorded, got %+v", ev.Manipulations)
		}
	}

	// 2. Virtual http://proxide.local portal request through proxy.
	portalResp, err := mitmClient.Get("http://proxide.local/ca.pem")
	if err != nil {
		t.Fatalf("proxide.local request failed: %v", err)
	}
	pemBytes, _ := io.ReadAll(portalResp.Body)
	_ = portalResp.Body.Close()
	if !bytes.Equal(pemBytes, auth.CertPEM()) {
		t.Fatal("http://proxide.local/ca.pem did not match Root CA PEM")
	}

	// 3. Cert-pin failure detection (client rejects Proxide CA), then passthrough bypass succeeds when trusting upstream!
	strictRoots := x509.NewCertPool()
	strictRoots.AddCert(upstream.Certificate())
	strictClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: strictRoots},
		},
	}

	if _, err := strictClient.Get(upstream.URL + "/api/pinned"); err == nil {
		t.Fatal("expected strict pinned client to fail MITM handshake")
	}
	var pinEvt model.CaptureEvent
	select {
	case pinEvt = <-streamCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pin-failure event")
	}
	if pinEvt.TLS == nil || !pinEvt.TLS.PinSuspected {
		t.Fatalf("expected PinSuspected=true on TLS failure event, got %+v", pinEvt.TLS)
	}

	// Add upstream host to passthrough allowlist and retry with strict pinned client.
	u, _ := url.Parse(upstream.URL)
	tlsMgr.UpdatePassthrough([]string{u.Hostname()}, nil)

	// Clear injected rule expectation by hitting non-/api path.
	passthroughResp, err := strictClient.Get(upstream.URL + "/raw-pinned")
	if err != nil {
		t.Fatalf("expected passthrough request to succeed for pinned client: %v", err)
	}
	_ = passthroughResp.Body.Close()
	strictClient.CloseIdleConnections()

	var ptEvt model.CaptureEvent
	select {
	case ptEvt = <-streamCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for passthrough event")
	}
	if ptEvt.Protocol != model.ProtocolTunnel || ptEvt.TLS == nil || !ptEvt.TLS.Passthrough {
		t.Fatalf("expected Passthrough tunnel event, got %+v", ptEvt)
	}
}
