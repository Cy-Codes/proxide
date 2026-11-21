package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"

	"proxide/internal/bus"
	"proxide/internal/clientreg"
	"proxide/internal/config"
	"proxide/internal/model"
	"proxide/internal/rewrite"
	"proxide/internal/tlsmitm"
)

// Options configures the LAN HTTP/HTTPS MITM proxy Handler.
type Options struct {
	Config        config.Config
	Logger        *slog.Logger
	Clients       clientreg.Resolver
	TLSManager    tlsmitm.ManagerInterface
	Interceptor   rewrite.Interceptor
	PortalHandler http.Handler
	Store         bus.FlowStore
	Publisher     bus.Publisher
}

// Handler serves LAN HTTP forward proxy requests, CONNECT tunnels, MITM TLS, and virtual portal routing.
type Handler struct {
	cfg           config.Config
	logger        *slog.Logger
	clients       clientreg.Resolver
	tlsMgr        tlsmitm.ManagerInterface
	interceptor   rewrite.Interceptor
	portalHandler http.Handler
	store         bus.FlowStore
	publisher     bus.Publisher
	transport     *http.Transport
}

// NewHandler constructs a proxy Handler with safe transport defaults (DisableCompression: true, no env proxy loops).
func NewHandler(opts Options) *Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	interceptor := opts.Interceptor
	if interceptor == nil {
		interceptor = rewrite.NoopInterceptor{}
	}
	clients := opts.Clients
	if clients == nil {
		clients = clientreg.NewRegistry(clientreg.Options{
			TagHeader:   opts.Config.ClientTagHeader,
			StripHeader: opts.Config.StripClientTag,
		})
	}

	dialer := &net.Dialer{
		Timeout:   config.DefaultDialTimeout,
		KeepAlive: config.DefaultIdleTimeout,
	}
	transport := &http.Transport{
		Proxy: nil, // Never re-read HTTP_PROXY env vars inside the proxy engine itself.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: opts.Config.InsecureUpstream,
		},
		TLSHandshakeTimeout:   config.DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: 0,
		DisableCompression:    true, // Preserve wire encodings faithfully (GP-23).
		MaxIdleConns:          128,
		IdleConnTimeout:       config.DefaultIdleTimeout,
	}

	return &Handler{
		cfg:           opts.Config,
		logger:        logger,
		clients:       clients,
		tlsMgr:        opts.TLSManager,
		interceptor:   interceptor,
		portalHandler: opts.PortalHandler,
		store:         opts.Store,
		publisher:     opts.Publisher,
		transport:     transport,
	}
}

// Close releases idle upstream transport connections cleanly during shutdown.
func (h *Handler) Close() {
	if h.transport != nil {
		h.transport.CloseIdleConnections()
	}
}

// ServeHTTP dispatches CONNECT tunnels, virtual portal requests, and HTTP forward proxy traffic.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer h.recoverPanic(w, r)

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	if h.isPortalRequest(r) && h.portalHandler != nil {
		h.portalHandler.ServeHTTP(w, r)
		return
	}

	if r.URL.Host == "" && r.Host == "" {
		http.Error(w, "bad proxy request: missing target host", http.StatusBadRequest)
		return
	}

	h.roundTripAndCapture(w, r, model.ProtocolHTTP, nil, "http")
}

func (h *Handler) isPortalRequest(r *http.Request) bool {
	if h.cfg.PortalHost != "" && strings.EqualFold(tlsmitm.NormalizeHost(r.Host), tlsmitm.NormalizeHost(h.cfg.PortalHost)) {
		return true
	}
	// Direct origin-form requests (e.g. GET /ca.pem without proxy absolute-URI scheme/host) route to setup portal.
	return r.URL.Scheme == "" && r.URL.Host == ""
}

func (h *Handler) emitEvent(evt model.CaptureEvent) {
	if h.store != nil {
		h.store.Append(evt)
	}
	if h.publisher != nil {
		h.publisher.Publish(evt)
	}
}

func (h *Handler) recoverPanic(w http.ResponseWriter, r *http.Request) {
	if rec := recover(); rec != nil {
		h.logger.ErrorContext(r.Context(), "recovered panic in proxy handler",
			"panic", rec,
			"method", r.Method,
			"host", r.Host,
			"stack", string(debug.Stack()),
		)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
