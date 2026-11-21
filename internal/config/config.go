package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxide/internal/model"
)

// Default network addresses, virtual portal host, and tagging header.
const (
	DefaultProxyAddr       = "0.0.0.0:8080"
	DefaultPortalAddr      = "0.0.0.0:8081"
	DefaultAPIAddr         = "127.0.0.1:9090"
	DefaultPortalHost      = "proxide.local"
	DefaultClientTagHeader = "X-Proxide-Client"
)

// Supported Root CA key algorithms.
const (
	DefaultCAAlgorithm = "ecdsa-p256"
	CAAlgorithmRSA2048 = "rsa-2048"
)

// Certificate policy, cache, ring-buffer, and I/O resource bounds.
const (
	DefaultLeafCertTTL         = 7 * 24 * time.Hour
	MaxAppleLeafCertTTL        = 397 * 24 * time.Hour
	LeafClockSkewBackdate      = 5 * time.Minute
	RootCAClockSkewBackdate    = 5 * time.Minute
	DefaultRootCATTL           = 10 * 365 * 24 * time.Hour
	DefaultCertCacheSize       = 2048
	CertRefreshMargin          = 1 * time.Hour
	DefaultMaxBodyCaptureBytes = 1 << 20
	DefaultRingBufferFlows     = 5000
	DefaultRingBufferMaxBytes  = 256 << 20
	DefaultSubscriberQueueSize = 256
	DefaultMaxAPIRequestBytes  = 1 << 20
	DefaultStateDirName        = ".proxide"
)

// Server and upstream dial timeouts.
const (
	DefaultReadHeaderTimeout   = 10 * time.Second
	DefaultIdleTimeout         = 120 * time.Second
	DefaultDialTimeout         = 15 * time.Second
	DefaultTLSHandshakeTimeout = 10 * time.Second
	DefaultShutdownTimeout     = 10 * time.Second
	DefaultDrainDiscardBytes   = 64 << 10
)

// Filesystem permission constants for CA directory and artifacts.
const (
	DirPermPrivate     = 0o700
	FilePermPrivateKey = 0o600
	FilePermPublicCert = 0o644
)

// Config holds immutable runtime settings for the proxide daemon.
type Config struct {
	ProxyAddr          string
	PortalAddr         string
	APIAddr            string
	InterfaceName      string
	PortalHost         string
	AllowRemoteAPI     bool
	APIToken           string
	CADir              string
	CAAlgorithm        string
	LeafCertTTL        time.Duration
	CertCacheSize      int
	ClientTagHeader    string
	StripClientTag     bool
	MaxBodyCaptureByte int64
	RingBufferFlows    int
	RingBufferMaxBytes int64
	SubscriberQueue    int
	PassthroughHosts   []string
	InsecureUpstream   bool
	MapLocalRoot       string
	Debug              bool
}

// Default returns a Config populated with safe, standard defaults.
func Default() Config {
	homeDir, err := os.UserHomeDir()
	stateDir := DefaultStateDirName
	if err == nil && homeDir != "" {
		stateDir = filepath.Join(homeDir, DefaultStateDirName)
	}
	return Config{
		ProxyAddr:          DefaultProxyAddr,
		PortalAddr:         DefaultPortalAddr,
		APIAddr:            DefaultAPIAddr,
		PortalHost:         DefaultPortalHost,
		CADir:              filepath.Join(stateDir, "ca"),
		CAAlgorithm:        DefaultCAAlgorithm,
		LeafCertTTL:        DefaultLeafCertTTL,
		CertCacheSize:      DefaultCertCacheSize,
		ClientTagHeader:    DefaultClientTagHeader,
		StripClientTag:     true,
		MaxBodyCaptureByte: DefaultMaxBodyCaptureBytes,
		RingBufferFlows:    DefaultRingBufferFlows,
		RingBufferMaxBytes: DefaultRingBufferMaxBytes,
		SubscriberQueue:    DefaultSubscriberQueueSize,
	}
}

// Validate checks configuration bounds and security invariants without mutating state.
func (c Config) Validate() error {
	if _, err := parseHostPort(c.ProxyAddr); err != nil {
		return fmt.Errorf("%w: proxy listen address %q: %w", model.ErrInvalidConfig, c.ProxyAddr, err)
	}
	if _, err := parseHostPort(c.PortalAddr); err != nil {
		return fmt.Errorf("%w: portal listen address %q: %w", model.ErrInvalidConfig, c.PortalAddr, err)
	}
	apiAP, err := parseHostPort(c.APIAddr)
	if err != nil {
		return fmt.Errorf("%w: api listen address %q: %w", model.ErrInvalidConfig, c.APIAddr, err)
	}
	if !apiAP.Addr().IsLoopback() {
		if !c.AllowRemoteAPI || strings.TrimSpace(c.APIToken) == "" {
			return fmt.Errorf("%w: non-loopback api address %q requires AllowRemoteAPI and a non-empty APIToken", model.ErrInvalidConfig, c.APIAddr)
		}
	}
	if c.CAAlgorithm != DefaultCAAlgorithm && c.CAAlgorithm != CAAlgorithmRSA2048 {
		return fmt.Errorf("%w: unsupported CA algorithm %q", model.ErrInvalidConfig, c.CAAlgorithm)
	}
	if c.LeafCertTTL <= 0 || c.LeafCertTTL > MaxAppleLeafCertTTL {
		return fmt.Errorf("%w: leaf TTL %s must be within (0, %s]", model.ErrInvalidLeafTTL, c.LeafCertTTL, MaxAppleLeafCertTTL)
	}
	if c.CertCacheSize <= 0 {
		return fmt.Errorf("%w: cert cache size must be positive", model.ErrInvalidConfig)
	}
	if c.MaxBodyCaptureByte <= 0 {
		return fmt.Errorf("%w: max body capture bytes must be positive", model.ErrInvalidConfig)
	}
	if c.RingBufferFlows <= 0 || c.RingBufferMaxBytes <= 0 {
		return fmt.Errorf("%w: ring buffer bounds must be positive", model.ErrInvalidConfig)
	}
	if c.SubscriberQueue <= 0 {
		return fmt.Errorf("%w: subscriber queue size must be positive", model.ErrInvalidConfig)
	}
	if strings.TrimSpace(c.CADir) == "" {
		return fmt.Errorf("%w: CA directory must not be empty", model.ErrInvalidConfig)
	}
	return nil
}

// LoadFromFlags parses CLI flags with environment-variable fallbacks into a validated Config.
func LoadFromFlags(args []string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	cfg := applyEnvOverrides(Default(), getenv)

	fs := flag.NewFlagSet("proxide", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var passthroughCSV string
	fs.StringVar(&cfg.ProxyAddr, "listen", cfg.ProxyAddr, "LAN proxy listen host:port")
	fs.StringVar(&cfg.PortalAddr, "portal-listen", cfg.PortalAddr, "LAN setup portal listen host:port")
	fs.StringVar(&cfg.APIAddr, "api-listen", cfg.APIAddr, "Loopback control/inspector API listen host:port")
	fs.StringVar(&cfg.InterfaceName, "iface", cfg.InterfaceName, "Optional LAN network interface name to bind/advertise")
	fs.StringVar(&cfg.PortalHost, "portal-host", cfg.PortalHost, "Virtual setup portal hostname intercepted through the proxy")
	fs.BoolVar(&cfg.AllowRemoteAPI, "allow-remote-api", cfg.AllowRemoteAPI, "Allow binding Control API outside loopback when api-token is set")
	fs.StringVar(&cfg.APIToken, "api-token", cfg.APIToken, "Bearer token required when Control API is non-loopback")
	fs.StringVar(&cfg.CADir, "ca-dir", cfg.CADir, "Directory holding persistent Root CA files")
	fs.StringVar(&cfg.CAAlgorithm, "ca-alg", cfg.CAAlgorithm, "Root CA algorithm: ecdsa-p256 or rsa-2048")
	fs.DurationVar(&cfg.LeafCertTTL, "leaf-ttl", cfg.LeafCertTTL, "Leaf certificate validity duration (<= 397d)")
	fs.IntVar(&cfg.CertCacheSize, "cert-cache-size", cfg.CertCacheSize, "Maximum cached dynamic SNI certificates")
	fs.StringVar(&cfg.ClientTagHeader, "tag-header", cfg.ClientTagHeader, "Custom request header used by controllers to tag flows")
	fs.BoolVar(&cfg.StripClientTag, "strip-tag-header", cfg.StripClientTag, "Strip custom client tag header before forwarding upstream")
	fs.Int64Var(&cfg.MaxBodyCaptureByte, "max-capture-bytes", cfg.MaxBodyCaptureByte, "Maximum request/response body bytes captured per flow")
	fs.IntVar(&cfg.RingBufferFlows, "ring-flows", cfg.RingBufferFlows, "Maximum flows retained in memory")
	fs.Int64Var(&cfg.RingBufferMaxBytes, "ring-bytes", cfg.RingBufferMaxBytes, "Maximum approximate bytes retained in flow store")
	fs.StringVar(&passthroughCSV, "passthrough", strings.Join(cfg.PassthroughHosts, ","), "Comma-separated hostnames or *.domain patterns to tunnel without MITM")
	fs.BoolVar(&cfg.InsecureUpstream, "insecure-upstream", cfg.InsecureUpstream, "Skip upstream TLS certificate verification (dev only)")
	fs.StringVar(&cfg.MapLocalRoot, "map-local-root", cfg.MapLocalRoot, "Root directory allowed for Map Local fixture files")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "Enable verbose diagnostics and detailed error messages")

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("%w: %w", model.ErrInvalidConfig, err)
	}
	cfg.PassthroughHosts = splitCSV(passthroughCSV)

	if cfg.InterfaceName != "" && cfg.ProxyAddr == DefaultProxyAddr {
		addrs, err := ResolveLANAddresses(cfg.InterfaceName)
		if err != nil {
			return Config{}, err
		}
		_, portStr, _ := net.SplitHostPort(cfg.ProxyAddr)
		cfg.ProxyAddr = net.JoinHostPort(addrs[0].String(), portStr)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ResolveLANAddresses lists non-loopback unicast LAN IP addresses (IPv4 preferred first).
// When ifaceName is non-empty, only addresses on that interface are returned.
func ResolveLANAddresses(ifaceName string) ([]netip.Addr, error) {
	var ifaces []net.Interface
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("%w: interface %q: %w", model.ErrInvalidConfig, ifaceName, err)
		}
		ifaces = []net.Interface{*iface}
	} else {
		list, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("list network interfaces: %w", err)
		}
		ifaces = list
	}

	var v4 []netip.Addr
	var v6 []netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		rawAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range rawAddrs {
			ipNet, ok := raw.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
				continue
			}
			if addr.Is4() {
				v4 = append(v4, addr)
			} else {
				v6 = append(v6, addr)
			}
		}
	}

	out := append(v4, v6...)
	if ifaceName != "" && len(out) == 0 {
		return nil, fmt.Errorf("%w: interface %q has no active non-loopback addresses", model.ErrInvalidConfig, ifaceName)
	}
	return out, nil
}

func applyEnvOverrides(cfg Config, getenv func(string) string) Config {
	if v := strings.TrimSpace(getenv("PROXIDE_LISTEN")); v != "" {
		cfg.ProxyAddr = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_PORTAL_LISTEN")); v != "" {
		cfg.PortalAddr = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_API_LISTEN")); v != "" {
		cfg.APIAddr = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_IFACE")); v != "" {
		cfg.InterfaceName = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_PORTAL_HOST")); v != "" {
		cfg.PortalHost = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_ALLOW_REMOTE_API")); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowRemoteAPI = b
		}
	}
	if v := getenv("PROXIDE_API_TOKEN"); v != "" {
		cfg.APIToken = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_CA_DIR")); v != "" {
		cfg.CADir = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_CA_ALG")); v != "" {
		cfg.CAAlgorithm = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_LEAF_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.LeafCertTTL = d
		}
	}
	if v := strings.TrimSpace(getenv("PROXIDE_TAG_HEADER")); v != "" {
		cfg.ClientTagHeader = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_PASSTHROUGH")); v != "" {
		cfg.PassthroughHosts = splitCSV(v)
	}
	if v := strings.TrimSpace(getenv("PROXIDE_MAP_LOCAL_ROOT")); v != "" {
		cfg.MapLocalRoot = v
	}
	if v := strings.TrimSpace(getenv("PROXIDE_DEBUG")); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Debug = b
		}
	}
	return cfg
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseHostPort(raw string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("port must be between 1 and 65535")
	}
	if host == "" {
		return netip.AddrPort{}, errors.New("host must not be empty")
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	if strings.EqualFold(host, "localhost") {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)), nil
	}
	// Accept valid DNS hostnames when explicitly configured (treated as non-loopback for API check).
	return netip.AddrPortFrom(netip.Addr{}, uint16(port)), nil
}
