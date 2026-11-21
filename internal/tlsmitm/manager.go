package tlsmitm

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxide/internal/config"
)

const (
	pinEOFThreshold    = 2
	maxPinFailureTrack = 4096
)

// LeafSigner signs on-demand TLS certificates for a normalized hostname or IP.
type LeafSigner interface {
	SignLeaf(host string, ttl time.Duration) (tls.Certificate, string, error)
}

// PinObservation records a client+host pair suspected of certificate pinning rejection.
type PinObservation struct {
	ClientIP  netip.Addr `json:"client_ip"`
	Host      string     `json:"host"`
	Failures  int        `json:"failures"`
	LastError string     `json:"last_error"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// PassthroughState exposes an immutable view of passthrough rules and suspected pins.
type PassthroughState struct {
	Hosts         []string         `json:"hosts"`
	ClientIPs     []netip.Addr     `json:"client_ips"`
	SuspectedPins []PinObservation `json:"suspected_pins"`
}

// ManagerInterface abstracts dynamic MITM TLS configuration and passthrough policy.
type ManagerInterface interface {
	ServerTLSConfig(fallbackHost string) *tls.Config
	LookupCachedSerial(host string) string
	ShouldPassthrough(clientIP netip.Addr, host string) bool
	RecordHandshakeFailure(clientIP netip.Addr, host string, err error) bool
	PassthroughSnapshot() PassthroughState
	UpdatePassthrough(hosts []string, clientIPs []netip.Addr)
}

type passthroughSnapshot struct {
	hosts     []string
	clientIPs map[netip.Addr]struct{}
	rawIPs    []netip.Addr
}

type pinKey struct {
	ip   netip.Addr
	host string
}

// Manager handles dynamic SNI leaf caching with singleflight deduplication and passthrough tracking.
type Manager struct {
	signer      LeafSigner
	leafTTL     time.Duration
	now         func() time.Time
	cache       *certLRU
	sf          singleflightGroup[string, cachedLeaf]
	passthrough atomic.Pointer[passthroughSnapshot]

	failMu      sync.Mutex
	pinFailures map[pinKey]PinObservation
}

// Options configures a MITM TLS Manager.
type Options struct {
	Signer           LeafSigner
	LeafTTL          time.Duration
	CacheSize        int
	PassthroughHosts []string
	PassthroughIPs   []netip.Addr
	Now              func() time.Time
}

// NewManager creates a Manager with bounded LRU certificate caching and passthrough state.
func NewManager(opts Options) *Manager {
	ttl := opts.LeafTTL
	if ttl <= 0 || ttl > config.MaxAppleLeafCertTTL {
		ttl = config.DefaultLeafCertTTL
	}
	cacheSize := opts.CacheSize
	if cacheSize <= 0 {
		cacheSize = config.DefaultCertCacheSize
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	m := &Manager{
		signer:      opts.Signer,
		leafTTL:     ttl,
		now:         nowFn,
		cache:       newCertLRU(cacheSize, config.CertRefreshMargin),
		pinFailures: make(map[pinKey]PinObservation),
	}
	m.UpdatePassthrough(opts.PassthroughHosts, opts.PassthroughIPs)
	return m
}

// NormalizeHost strips optional port, IPv6 brackets, trailing dots, and lowercases the host.
func NormalizeHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	trimmed = strings.TrimPrefix(trimmed, "[")
	trimmed = strings.TrimSuffix(trimmed, "]")
	trimmed = strings.TrimSuffix(trimmed, ".")
	return strings.ToLower(trimmed)
}

// MatchHostPattern matches an exact normalized host or single/multi-level *.domain wildcard pattern.
func MatchHostPattern(pattern, host string) bool {
	normPattern := NormalizeHost(pattern)
	normHost := NormalizeHost(host)
	if normPattern == "" || normHost == "" {
		return false
	}
	if strings.HasPrefix(normPattern, "*.") {
		suffix := normPattern[1:] // ".example.com"
		return strings.HasSuffix(normHost, suffix) && len(normHost) > len(suffix)
	}
	return normPattern == normHost
}

// ServerTLSConfig returns a per-connection *tls.Config whose GetCertificate signs SNI leaves on demand.
func (m *Manager) ServerTLSConfig(fallbackHost string) *tls.Config {
	fallback := NormalizeHost(fallbackHost)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Keep ALPN explicitly pinned to HTTP/1.1 until HTTP/2 MITM frame support is implemented.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			target := ""
			if hello != nil {
				target = NormalizeHost(hello.ServerName)
			}
			if target == "" {
				target = fallback
			}
			return m.getOrSignCert(target)
		},
	}
}

func (m *Manager) getOrSignCert(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, errors.New("missing SNI and fallback host for TLS leaf certificate")
	}

	now := m.now().UTC()
	if cert, _, ok := m.cache.Get(host, now); ok {
		return cert, nil
	}

	// Deduplicate concurrent leaf signing per SNI outside the LRU lock.
	entry, err, _ := m.sf.Do(host, func() (cachedLeaf, error) {
		if cert, serial, ok := m.cache.Get(host, m.now().UTC()); ok {
			return cachedLeaf{
				key:       host,
				cert:      cert,
				serial:    serial,
				expiresAt: cert.Leaf.NotAfter,
			}, nil
		}

		signed, serial, signErr := m.signer.SignLeaf(host, m.leafTTL)
		if signErr != nil {
			return cachedLeaf{}, signErr
		}
		certPtr := &signed
		exp := m.now().UTC().Add(m.leafTTL)
		if certPtr.Leaf != nil {
			exp = certPtr.Leaf.NotAfter
		}
		m.cache.Put(host, certPtr, serial, exp)
		return cachedLeaf{
			key:       host,
			cert:      certPtr,
			serial:    serial,
			expiresAt: exp,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return entry.cert, nil
}

// LookupCachedSerial returns the currently cached leaf hex serial for host if present.
func (m *Manager) LookupCachedSerial(host string) string {
	norm := NormalizeHost(host)
	if norm == "" {
		return ""
	}
	_, serial, ok := m.cache.Get(norm, m.now().UTC())
	if !ok {
		return ""
	}
	return serial
}

// ShouldPassthrough reports whether traffic from clientIP to host should bypass MITM via raw TCP tunnel.
func (m *Manager) ShouldPassthrough(clientIP netip.Addr, host string) bool {
	snap := m.passthrough.Load()
	if snap == nil {
		return false
	}
	unmapped := clientIP.Unmap()
	if unmapped.IsValid() {
		if _, ok := snap.clientIPs[unmapped]; ok {
			return true
		}
	}
	normHost := NormalizeHost(host)
	for _, pat := range snap.hosts {
		if MatchHostPattern(pat, normHost) {
			return true
		}
	}
	return false
}

// UpdatePassthrough atomically replaces the passthrough host pattern and client IP allowlists.
func (m *Manager) UpdatePassthrough(hosts []string, clientIPs []netip.Addr) {
	cleanHosts := make([]string, 0, len(hosts))
	seenHost := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		norm := NormalizeHost(h)
		if norm == "" {
			continue
		}
		if _, exists := seenHost[norm]; exists {
			continue
		}
		seenHost[norm] = struct{}{}
		cleanHosts = append(cleanHosts, norm)
	}
	slices.Sort(cleanHosts)

	ipSet := make(map[netip.Addr]struct{}, len(clientIPs))
	cleanIPs := make([]netip.Addr, 0, len(clientIPs))
	for _, ip := range clientIPs {
		u := ip.Unmap()
		if !u.IsValid() {
			continue
		}
		if _, exists := ipSet[u]; exists {
			continue
		}
		ipSet[u] = struct{}{}
		cleanIPs = append(cleanIPs, u)
	}
	slices.SortFunc(cleanIPs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	m.passthrough.Store(&passthroughSnapshot{
		hosts:     cleanHosts,
		clientIPs: ipSet,
		rawIPs:    cleanIPs,
	})
}

// RecordHandshakeFailure tracks client-side TLS handshake errors and reports whether certificate pinning is suspected.
func (m *Manager) RecordHandshakeFailure(clientIP netip.Addr, host string, err error) bool {
	if err == nil {
		return false
	}
	normHost := NormalizeHost(host)
	ip := clientIP.Unmap()
	errText := strings.ToLower(err.Error())

	explicitCertAlert := strings.Contains(errText, "bad certificate") ||
		strings.Contains(errText, "unknown certificate") ||
		strings.Contains(errText, "certificate unknown") ||
		strings.Contains(errText, "unknown ca") ||
		strings.Contains(errText, "access denied")
	eofAbort := errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(errText, "eof") ||
		strings.Contains(errText, "connection reset")

	if !explicitCertAlert && !eofAbort {
		return false
	}

	key := pinKey{ip: ip, host: normHost}
	now := m.now().UTC()

	m.failMu.Lock()
	defer m.failMu.Unlock()

	if len(m.pinFailures) >= maxPinFailureTrack {
		if _, exists := m.pinFailures[key]; !exists {
			// Clear stale tracking map when saturated to preserve bounded memory.
			clear(m.pinFailures)
		}
	}

	obs := m.pinFailures[key]
	obs.ClientIP = ip
	obs.Host = normHost
	obs.Failures++
	obs.LastError = err.Error()
	obs.UpdatedAt = now
	m.pinFailures[key] = obs

	return explicitCertAlert || obs.Failures >= pinEOFThreshold
}

// PassthroughSnapshot returns an immutable snapshot of active passthrough allowlists and suspected pin events.
func (m *Manager) PassthroughSnapshot() PassthroughState {
	snap := m.passthrough.Load()
	hosts := []string{}
	ips := []netip.Addr{}
	if snap != nil {
		hosts = slices.Clone(snap.hosts)
		ips = slices.Clone(snap.rawIPs)
	}

	m.failMu.Lock()
	pins := make([]PinObservation, 0, len(m.pinFailures))
	for _, obs := range m.pinFailures {
		pins = append(pins, obs)
	}
	m.failMu.Unlock()

	slices.SortFunc(pins, func(a, b PinObservation) int {
		if cmp := a.ClientIP.Compare(b.ClientIP); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Host, b.Host)
	})

	return PassthroughState{
		Hosts:         hosts,
		ClientIPs:     ips,
		SuspectedPins: pins,
	}
}
