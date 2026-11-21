package portal

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"proxide/internal/ca"
	"proxide/internal/config"
)

//go:embed templates/index.html
var templateFS embed.FS

var indexTemplate = template.Must(template.ParseFS(templateFS, "templates/index.html"))

// Options configures the read-only LAN Setup Portal HTTP handler.
type Options struct {
	CAProvider  ca.PublicProvider
	ProxyHost   string
	ProxyPort   string
	PortalHost  string
	PortalPort  string
	DefaultHost string
}

// Handler serves read-only device onboarding instructions and public Root CA downloads.
type Handler struct {
	ca         ca.PublicProvider
	proxyHost  string
	proxyPort  string
	portalHost string
	portalPort string
}

type pageView struct {
	Guide       DeviceGuide
	ProxyHost   string
	ProxyPort   string
	PortalHost  string
	Fingerprint string
}

type fingerprintResponse struct {
	Fingerprint string    `json:"fingerprint"`
	ProxyHost   string    `json:"proxy_host"`
	ProxyPort   string    `json:"proxy_port"`
	PortalHost  string    `json:"portal_host"`
	NotAfter    time.Time `json:"not_after"`
}

// NewHandler constructs a strictly read-only Setup Portal http.Handler.
func NewHandler(opts Options) *Handler {
	proxyHost := strings.TrimSpace(opts.ProxyHost)
	if proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	proxyPort := strings.TrimSpace(opts.ProxyPort)
	if proxyPort == "" {
		proxyPort = "8080"
	}
	portalHost := strings.TrimSpace(opts.PortalHost)
	if portalHost == "" {
		portalHost = config.DefaultPortalHost
	}
	portalPort := strings.TrimSpace(opts.PortalPort)
	if portalPort == "" {
		portalPort = "8081"
	}
	return &Handler{
		ca:         opts.CAProvider,
		proxyHost:  proxyHost,
		proxyPort:  proxyPort,
		portalHost: portalHost,
		portalPort: portalPort,
	}
}

// ServeHTTP handles read-only GET/HEAD requests for onboarding pages and public Root CA files.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	switch r.URL.Path {
	case "/", "/index.html":
		h.serveIndex(w, r)
	case "/ca.pem":
		h.serveCert(w, r, "application/x-pem-file", "proxide-ca.pem", h.ca.CertPEM())
	case "/ca.cer":
		h.serveCert(w, r, "application/pkix-cert", "proxide-ca.cer", h.ca.CertDER())
	case "/ca.der":
		h.serveCert(w, r, "application/pkix-cert", "proxide-ca.der", h.ca.CertDER())
	case "/ca.crt":
		h.serveCert(w, r, "application/x-x509-ca-cert", "proxide-ca.crt", h.ca.CertPEM())
	case "/fingerprint":
		h.serveFingerprint(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	platform := ClassifyUserAgent(r.Header.Get("User-Agent"))
	if rawOverride := r.URL.Query().Get("platform"); rawOverride != "" {
		if parsed, ok := ParsePlatformOverride(rawOverride); ok {
			platform = parsed
		}
	}

	displayHost := h.resolveDisplayHost(r.Host)
	portalURL := fmt.Sprintf("http://%s:%s", displayHost, h.portalPort)
	if strings.EqualFold(stripPort(r.Host), h.portalHost) {
		portalURL = fmt.Sprintf("http://%s", h.portalHost)
	}

	view := pageView{
		Guide:       BuildDeviceGuide(platform, displayHost, h.proxyPort, portalURL),
		ProxyHost:   displayHost,
		ProxyPort:   h.proxyPort,
		PortalHost:  h.portalHost,
		Fingerprint: h.ca.SHA256Fingerprint(),
	}

	var buf bytes.Buffer
	if err := indexTemplate.Execute(&buf, view); err != nil {
		http.Error(w, "failed to render portal template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(buf.Bytes())
	}
}

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request, contentType, filename string, payload []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(payload)
	}
}

func (h *Handler) serveFingerprint(w http.ResponseWriter, r *http.Request) {
	displayHost := h.resolveDisplayHost(r.Host)
	payload := fingerprintResponse{
		Fingerprint: h.ca.SHA256Fingerprint(),
		ProxyHost:   displayHost,
		ProxyPort:   h.proxyPort,
		PortalHost:  h.portalHost,
		NotAfter:    h.ca.NotAfter(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "failed to encode fingerprint response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(encoded)
	}
}

func (h *Handler) resolveDisplayHost(reqHost string) string {
	host := stripPort(reqHost)
	if host == "" || strings.EqualFold(host, h.portalHost) || host == "0.0.0.0" {
		return h.proxyHost
	}
	return host
}

func stripPort(raw string) string {
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return strings.TrimSpace(raw)
}
