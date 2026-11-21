package clientreg

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	arpCacheTTL     = 30 * time.Second
	arpLookupWindow = 500 * time.Millisecond
)

// MACResolver resolves best-effort hardware MAC addresses for LAN IP addresses without root privileges.
type MACResolver interface {
	LookupMAC(ctx context.Context, ip netip.Addr) string
}

// NoopMACResolver disables OS neighbor cache lookups (useful for deterministic tests).
type NoopMACResolver struct{}

// LookupMAC always returns an empty string.
func (NoopMACResolver) LookupMAC(context.Context, netip.Addr) string {
	return ""
}

// ARPCacheResolver queries the OS ARP table with a short in-memory TTL cache.
type ARPCacheResolver struct {
	mu        sync.RWMutex
	entries   map[netip.Addr]string
	refreshed time.Time
	now       func() time.Time
}

// NewARPCacheResolver constructs a best-effort cached OS ARP lookup resolver.
func NewARPCacheResolver() *ARPCacheResolver {
	return &ARPCacheResolver{
		entries: make(map[netip.Addr]string),
		now:     time.Now,
	}
}

// LookupMAC returns a cached or freshly parsed MAC address for ip, or "" if unavailable.
func (r *ARPCacheResolver) LookupMAC(ctx context.Context, ip netip.Addr) string {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() {
		return ""
	}

	r.mu.RLock()
	fresh := !r.refreshed.IsZero() && r.now().Sub(r.refreshed) < arpCacheTTL
	mac := r.entries[ip]
	r.mu.RUnlock()
	if fresh {
		return mac
	}

	r.refresh(ctx)

	r.mu.RLock()
	mac = r.entries[ip]
	r.mu.RUnlock()
	return mac
}

func (r *ARPCacheResolver) refresh(ctx context.Context) {
	lookupCtx, cancel := context.WithTimeout(ctx, arpLookupWindow)
	defer cancel()

	out, err := exec.CommandContext(lookupCtx, "arp", "-an").Output()
	if err != nil {
		// Record refresh attempt so unavailable arp binary does not retry on every flow.
		r.mu.Lock()
		r.refreshed = r.now()
		r.mu.Unlock()
		return
	}

	parsed := ParseARPOutput(string(out))
	r.mu.Lock()
	r.entries = parsed
	r.refreshed = r.now()
	r.mu.Unlock()
}

// ParseARPOutput extracts normalized IP -> MAC mappings from BSD/macOS and Linux `arp -an` output.
func ParseARPOutput(raw string) map[netip.Addr]string {
	result := make(map[netip.Addr]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		openIdx := strings.IndexByte(line, '(')
		closeIdx := strings.IndexByte(line, ')')
		if openIdx < 0 || closeIdx <= openIdx+1 {
			continue
		}
		ipStr := line[openIdx+1 : closeIdx]
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		ip = ip.Unmap()

		fields := strings.Fields(line[closeIdx+1:])
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "at" {
				if mac, ok := normalizeMAC(fields[i+1]); ok {
					result[ip] = mac
				}
				break
			}
		}
	}
	return result
}

func normalizeMAC(raw string) (string, bool) {
	if raw == "" || raw == "(incomplete)" || strings.EqualFold(raw, "incomplete") {
		return "", false
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
	if len(parts) != 6 {
		return "", false
	}
	padded := make([]string, 6)
	for i, part := range parts {
		if len(part) == 0 || len(part) > 2 {
			return "", false
		}
		for j := 0; j < len(part); j++ {
			c := part[j]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return "", false
			}
		}
		if len(part) == 1 {
			padded[i] = fmt.Sprintf("0%s", part)
		} else {
			padded[i] = part
		}
	}
	return strings.Join(padded, ":"), true
}
