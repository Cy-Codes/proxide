package clientreg

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"proxide/internal/model"
)

const maxClientTagRunes = 128

// Resolver resolves and tracks LAN devices and tagged local controllers.
type Resolver interface {
	Resolve(ctx context.Context, remoteAddr string, headers http.Header, platform model.DevicePlatform) model.ClientIdentity
	SetAlias(ip netip.Addr, friendlyName string) model.ClientRecord
	List() []model.ClientRecord
}

type clientEntry struct {
	identity  model.ClientIdentity
	flowCount uint64
	firstSeen time.Time
	lastSeen  time.Time
}

// Registry maintains thread-safe per-IP client metadata, friendly aliases, and observed tags.
type Registry struct {
	mu          sync.RWMutex
	tagHeader   string
	stripHeader bool
	macResolver MACResolver
	now         func() time.Time
	clients     map[netip.Addr]*clientEntry
	aliases     map[netip.Addr]string
}

// Options configures a client Registry.
type Options struct {
	TagHeader   string
	StripHeader bool
	MACResolver MACResolver
	Now         func() time.Time
}

// NewRegistry creates a thread-safe client Registry.
func NewRegistry(opts Options) *Registry {
	macResolver := opts.MACResolver
	if macResolver == nil {
		macResolver = NewARPCacheResolver()
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Registry{
		tagHeader:   strings.TrimSpace(opts.TagHeader),
		stripHeader: opts.StripHeader,
		macResolver: macResolver,
		now:         nowFn,
		clients:     make(map[netip.Addr]*clientEntry),
		aliases:     make(map[netip.Addr]string),
	}
}

// NormalizeRemoteAddr parses a peer host:port or IP string and unmaps IPv4-mapped IPv6 addresses.
func NormalizeRemoteAddr(remoteAddr string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(remoteAddr)
	if ap, err := netip.ParseAddrPort(trimmed); err == nil {
		return ap.Addr().Unmap(), nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

// ExtractClientTag reads an optional controller tag header and optionally strips it before forwarding upstream.
func ExtractClientTag(headers http.Header, headerName string, strip bool) string {
	if headers == nil || strings.TrimSpace(headerName) == "" {
		return ""
	}
	val := strings.TrimSpace(headers.Get(headerName))
	if strip {
		headers.Del(headerName)
	}
	return truncateRunes(val, maxClientTagRunes)
}

// Resolve normalizes the client source IP, extracts any controller tag, enriches MAC/friendly name, and updates stats.
func (r *Registry) Resolve(
	ctx context.Context,
	remoteAddr string,
	headers http.Header,
	platform model.DevicePlatform,
) model.ClientIdentity {
	ip, err := NormalizeRemoteAddr(remoteAddr)
	tag := ExtractClientTag(headers, r.tagHeader, r.stripHeader)
	if platform == "" {
		platform = model.PlatformUnknown
	}
	if err != nil || !ip.IsValid() {
		return model.ClientIdentity{
			Tag:      tag,
			Platform: platform,
		}
	}

	mac := r.macResolver.LookupMAC(ctx, ip)
	ts := r.now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()

	alias := r.aliases[ip]
	entry, ok := r.clients[ip]
	if !ok {
		entry = &clientEntry{
			identity: model.ClientIdentity{
				IP:           ip,
				Tag:          tag,
				FriendlyName: alias,
				MAC:          mac,
				Platform:     platform,
			},
			firstSeen: ts,
		}
		r.clients[ip] = entry
	} else {
		if alias != "" {
			entry.identity.FriendlyName = alias
		}
		if mac != "" {
			entry.identity.MAC = mac
		}
		if platform != model.PlatformUnknown {
			entry.identity.Platform = platform
		}
		if tag != "" {
			entry.identity.Tag = tag
		}
	}
	entry.flowCount++
	entry.lastSeen = ts

	identity := entry.identity
	// Preserve per-flow tag when present on this specific request even if another controller shares the IP.
	if tag != "" {
		identity.Tag = tag
	}
	return identity
}

// SetAlias assigns or clears an operator-defined friendly alias for a normalized client IP.
func (r *Registry) SetAlias(ip netip.Addr, friendlyName string) model.ClientRecord {
	ip = ip.Unmap()
	name := truncateRunes(strings.TrimSpace(friendlyName), maxClientTagRunes)
	ts := r.now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()

	if name == "" {
		delete(r.aliases, ip)
	} else {
		r.aliases[ip] = name
	}

	entry, ok := r.clients[ip]
	if !ok {
		entry = &clientEntry{
			identity: model.ClientIdentity{
				IP:           ip,
				FriendlyName: name,
				Platform:     model.PlatformUnknown,
			},
			firstSeen: ts,
			lastSeen:  ts,
		}
		r.clients[ip] = entry
	} else {
		entry.identity.FriendlyName = name
	}

	return model.ClientRecord{
		ClientIdentity: entry.identity,
		FlowCount:      entry.flowCount,
		FirstSeen:      entry.firstSeen,
		LastSeen:       entry.lastSeen,
	}
}

// List returns a deterministic snapshot of all observed and aliased clients.
func (r *Registry) List() []model.ClientRecord {
	r.mu.RLock()
	out := make([]model.ClientRecord, 0, len(r.clients))
	for _, entry := range r.clients {
		out = append(out, model.ClientRecord{
			ClientIdentity: entry.identity,
			FlowCount:      entry.flowCount,
			FirstSeen:      entry.firstSeen,
			LastSeen:       entry.lastSeen,
		})
	}
	r.mu.RUnlock()

	slices.SortFunc(out, func(a, b model.ClientRecord) int {
		return a.IP.Compare(b.IP)
	})
	return out
}

func truncateRunes(s string, max int) string {
	if max <= 0 || s == "" {
		return ""
	}
	count := 0
	for i := range s {
		if count == max {
			return s[:i]
		}
		count++
	}
	return s
}
