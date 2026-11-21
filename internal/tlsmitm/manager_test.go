package tlsmitm

import (
	"crypto/tls"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxide/internal/ca"
	"proxide/internal/config"
)

type countingSigner struct {
	inner LeafSigner
	calls atomic.Int64
}

func (c *countingSigner) SignLeaf(host string, ttl time.Duration) (tls.Certificate, string, error) {
	c.calls.Add(1)
	time.Sleep(15 * time.Millisecond)
	return c.inner.SignLeaf(host, ttl)
}

func TestGetCertificateSingleflightAndLRUCache(t *testing.T) {
	t.Parallel()
	auth, err := ca.LoadOrCreate(ca.Options{
		Dir:       filepath.Join(t.TempDir(), "ca"),
		Algorithm: config.DefaultCAAlgorithm,
	})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	signer := &countingSigner{inner: auth}
	mgr := NewManager(Options{
		Signer:    signer,
		LeafTTL:   config.DefaultLeafCertTTL,
		CacheSize: 8,
	})

	tlsCfg := mgr.ServerTLSConfig("fallback.example.com")
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected NextProtos=[http/1.1], got %v", tlsCfg.NextProtos)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, gErr := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "cdn.example.com"})
			if gErr != nil {
				errs <- gErr
			}
		}()
	}
	wg.Wait()
	close(errs)

	for gErr := range errs {
		t.Fatalf("GetCertificate error: %v", gErr)
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("expected singleflight to sign once, got %d calls", signer.calls.Load())
	}

	// Second call must hit cache without signing again.
	if _, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "CDN.EXAMPLE.COM"}); err != nil {
		t.Fatalf("cached GetCertificate failed: %v", err)
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("expected cache hit, got %d calls", signer.calls.Load())
	}

	// Empty SNI should fall back cleanly to CONNECT host.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("fallback GetCertificate failed: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.DNSNames[0] != "fallback.example.com" {
		t.Fatalf("unexpected fallback leaf cert: %+v", cert.Leaf)
	}
}

func TestPassthroughMatchingAndPinDetection(t *testing.T) {
	t.Parallel()
	auth, err := ca.LoadOrCreate(ca.Options{Dir: filepath.Join(t.TempDir(), "ca")})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	ip1 := netip.MustParseAddr("192.168.1.20")
	ip2 := netip.MustParseAddr("192.168.1.30")

	mgr := NewManager(Options{
		Signer:           auth,
		PassthroughHosts: []string{"*.roku.com", "pin.example.com:443"},
		PassthroughIPs:   []netip.Addr{ip1},
	})

	if !mgr.ShouldPassthrough(ip2, "api.roku.com:443") {
		t.Fatal("expected wildcard *.roku.com to match api.roku.com:443")
	}
	if !mgr.ShouldPassthrough(ip1, "anything.example.org") {
		t.Fatal("expected passthrough client IP to bypass MITM")
	}
	if mgr.ShouldPassthrough(ip2, "roku.com") {
		t.Fatal("did not expect *.roku.com to match bare apex roku.com")
	}

	if mgr.RecordHandshakeFailure(ip2, "pinned.app", io.EOF) {
		t.Fatal("first EOF alone should not flag pin immediately")
	}
	if !mgr.RecordHandshakeFailure(ip2, "pinned.app", io.EOF) {
		t.Fatal("second consecutive EOF should flag pin suspected")
	}
	if !mgr.RecordHandshakeFailure(ip2, "other.app", errors.New("remote error: tls: bad certificate")) {
		t.Fatal("explicit TLS bad certificate alert should flag pin suspected immediately")
	}

	state := mgr.PassthroughSnapshot()
	if len(state.SuspectedPins) != 2 {
		t.Fatalf("expected 2 pin observations, got %d", len(state.SuspectedPins))
	}
}
