package ca

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxide/internal/config"
	"proxide/internal/model"
)

func TestLoadOrCreatePermissionsAndReuse(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "ca-state")

	auth1, err := LoadOrCreate(Options{Dir: dir, Algorithm: config.DefaultCAAlgorithm})
	if err != nil {
		t.Fatalf("LoadOrCreate failed: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat ca dir: %v", err)
	}
	if dirInfo.Mode().Perm() != config.DirPermPrivate {
		t.Fatalf("dir mode = %o, want %o", dirInfo.Mode().Perm(), config.DirPermPrivate)
	}

	keyInfo, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("stat ca key: %v", err)
	}
	if keyInfo.Mode().Perm() != config.FilePermPrivateKey {
		t.Fatalf("key mode = %o, want %o", keyInfo.Mode().Perm(), config.FilePermPrivateKey)
	}

	certInfo, err := os.Stat(filepath.Join(dir, certFileName))
	if err != nil {
		t.Fatalf("stat ca cert: %v", err)
	}
	if certInfo.Mode().Perm() != config.FilePermPublicCert {
		t.Fatalf("cert mode = %o, want %o", certInfo.Mode().Perm(), config.FilePermPublicCert)
	}

	// Second LoadOrCreate must load existing CA without rotating fingerprint.
	auth2, err := LoadOrCreate(Options{Dir: dir, Algorithm: config.DefaultCAAlgorithm})
	if err != nil {
		t.Fatalf("second LoadOrCreate failed: %v", err)
	}
	if auth1.SHA256Fingerprint() != auth2.SHA256Fingerprint() {
		t.Fatalf("expected existing CA fingerprint to persist across loads")
	}
}

func TestSignLeafPolicyComplianceAndUniqueSerials(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "ca")
	fixedNow := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	auth, err := LoadOrCreate(Options{
		Dir:       dir,
		Algorithm: config.DefaultCAAlgorithm,
		Now:       func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Reject TTL exceeding Apple's 397-day limit.
	if _, _, err := auth.SignLeaf("api.example.com", config.MaxAppleLeafCertTTL+time.Hour); !errors.Is(err, model.ErrInvalidLeafTTL) {
		t.Fatalf("expected ErrInvalidLeafTTL, got: %v", err)
	}

	dnsCert, serial1, err := auth.SignLeaf("api.example.com.", config.DefaultLeafCertTTL)
	if err != nil {
		t.Fatalf("SignLeaf DNS failed: %v", err)
	}
	leaf := dnsCert.Leaf
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "api.example.com" {
		t.Fatalf("unexpected DNS SANs: %v", leaf.DNSNames)
	}
	if !leaf.NotBefore.Equal(fixedNow.Add(-config.LeafClockSkewBackdate)) {
		t.Fatalf("unexpected NotBefore: %v", leaf.NotBefore)
	}
	if leaf.NotAfter.Sub(fixedNow) != config.DefaultLeafCertTTL {
		t.Fatalf("unexpected NotAfter delta: %v", leaf.NotAfter.Sub(fixedNow))
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected ExtKeyUsage: %v", leaf.ExtKeyUsage)
	}

	// Verify signed chain against Root CA pool.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(auth.CertPEM()) {
		t.Fatal("failed to parse Root CA PEM")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "api.example.com",
		Roots:       roots,
		CurrentTime: fixedNow,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf certificate verification failed: %v", err)
	}

	// Verify IP literal SANs and unique serial numbers.
	ipCert, serial2, err := auth.SignLeaf("192.168.1.55", config.DefaultLeafCertTTL)
	if err != nil {
		t.Fatalf("SignLeaf IP failed: %v", err)
	}
	if serial1 == serial2 {
		t.Fatalf("expected unique random serials, both were %s", serial1)
	}
	if len(ipCert.Leaf.IPAddresses) != 1 || ipCert.Leaf.IPAddresses[0].String() != "192.168.1.55" {
		t.Fatalf("unexpected IP SANs: %v", ipCert.Leaf.IPAddresses)
	}
}
