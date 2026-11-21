package portal

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"proxide/internal/ca"
	"proxide/internal/model"
)

func TestClassifyUserAgentMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ua   string
		want model.DevicePlatform
	}{
		{ua: "Mozilla/5.0 (Linux; Android 9; AFTKA Build/PS7652) AppleWebKit/537.36 Silk/108.4", want: model.PlatformFireTV},
		{ua: "Mozilla/5.0 (Linux; Android 12; SHIELD Android TV Build/SR1A) AppleWebKit/537.36", want: model.PlatformAndroidTV},
		{ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile Safari/537.36", want: model.PlatformAndroid},
		{ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1", want: model.PlatformIOS},
		{ua: "AppleTV14,1/18.1 tvOS/18.1", want: model.PlatformTVOS},
		{ua: "curl/8.7.1", want: model.PlatformCLIController},
		{ua: "python-requests/2.32.3", want: model.PlatformCLIController},
		{ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0.0.0", want: model.PlatformDesktop},
		{ua: "", want: model.PlatformUnknown},
	}

	for _, tc := range cases {
		t.Run(string(tc.want)+":"+tc.ua, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyUserAgent(tc.ua); got != tc.want {
				t.Fatalf("ClassifyUserAgent(%q) = %s, want %s", tc.ua, got, tc.want)
			}
		})
	}
}

func FuzzClassifyUserAgent(f *testing.F) {
	f.Add("Mozilla/5.0 (Linux; Android 9; AFTKA) Silk/108")
	f.Add("AppleTV14,1/18.1")
	f.Add("curl/8.7.1")
	f.Add("")
	f.Fuzz(func(t *testing.T, ua string) {
		got := ClassifyUserAgent(ua)
		if got == "" {
			t.Fatal("ClassifyUserAgent returned empty DevicePlatform")
		}
	})
}

func TestPortalReadOnlyAndCertDownloadsNeverLeakPrivateKey(t *testing.T) {
	t.Parallel()
	auth, err := ca.LoadOrCreate(ca.Options{Dir: filepath.Join(t.TempDir(), "ca")})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	h := NewHandler(Options{
		CAProvider: auth,
		ProxyHost:  "192.168.1.10",
		ProxyPort:  "8080",
		PortalHost: "proxide.local",
		PortalPort: "8081",
	})

	// Reject mutating methods strictly.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/ca.pem", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /ca.pem = %d, want 405", method, rec.Code)
		}
	}

	// Verify HTML guide detects Fire TV UA and contains adb command.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "proxide.local"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 9; AFTMM) Silk/110")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Amazon Fire TV") || !strings.Contains(body, "adb shell settings put global http_proxy") {
		t.Fatalf("expected Fire TV guide and adb helper in HTML: %s", body)
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("portal HTML leaked private key marker")
	}

	// Verify PEM download parses as public cert only.
	pemRec := httptest.NewRecorder()
	h.ServeHTTP(pemRec, httptest.NewRequest(http.MethodGet, "/ca.pem", nil))
	if pemRec.Code != http.StatusOK || pemRec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("unexpected /ca.pem response: code=%d ct=%q", pemRec.Code, pemRec.Header().Get("Content-Type"))
	}
	if strings.Contains(pemRec.Body.String(), "PRIVATE KEY") {
		t.Fatal("/ca.pem leaked private key")
	}
	block, _ := pem.Decode(pemRec.Body.Bytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("invalid PEM certificate block: %+v", block)
	}

	// Verify DER/CER download parses as X.509 cert.
	cerRec := httptest.NewRecorder()
	h.ServeHTTP(cerRec, httptest.NewRequest(http.MethodGet, "/ca.cer", nil))
	if cerRec.Code != http.StatusOK || cerRec.Header().Get("Content-Type") != "application/pkix-cert" {
		t.Fatalf("unexpected /ca.cer response: code=%d ct=%q", cerRec.Code, cerRec.Header().Get("Content-Type"))
	}
	if _, err := x509.ParseCertificate(cerRec.Body.Bytes()); err != nil {
		t.Fatalf("failed to parse /ca.cer DER bytes: %v", err)
	}

	// Verify JSON fingerprint response.
	fpRec := httptest.NewRecorder()
	h.ServeHTTP(fpRec, httptest.NewRequest(http.MethodGet, "/fingerprint", nil))
	var fp fingerprintResponse
	if err := json.Unmarshal(fpRec.Body.Bytes(), &fp); err != nil {
		t.Fatalf("decode /fingerprint: %v", err)
	}
	if fp.Fingerprint != auth.SHA256Fingerprint() {
		t.Fatalf("fingerprint mismatch: %q != %q", fp.Fingerprint, auth.SHA256Fingerprint())
	}
}
