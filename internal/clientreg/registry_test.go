package clientreg

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"proxide/internal/model"
)

type stubMACResolver map[netip.Addr]string

func (s stubMACResolver) LookupMAC(_ context.Context, ip netip.Addr) string {
	return s[ip.Unmap()]
}

func TestNormalizeRemoteAddrUnmapsIPv4MappedIPv6(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "ipv4 with port", raw: "192.168.1.42:54321", want: "192.168.1.42"},
		{name: "ipv4-mapped ipv6 with port", raw: "[::ffff:192.168.1.42]:54321", want: "192.168.1.42"},
		{name: "pure ipv6 with port", raw: "[fe80::1]:8080", want: "fe80::1"},
		{name: "bare ipv4-mapped ipv6", raw: "::ffff:10.0.0.5", want: "10.0.0.5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeRemoteAddr(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("got %s, want %s", got.String(), tc.want)
			}
			if got.Is4In6() {
				t.Fatalf("expected unmapped address, got %s", got.String())
			}
		})
	}
}

func TestRegistryTagExtractionFriendlyAliasAndMAC(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.168.1.77")
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	reg := NewRegistry(Options{
		TagHeader:   "X-Proxide-Client",
		StripHeader: true,
		MACResolver: stubMACResolver{ip: "aa:bb:cc:dd:ee:ff"},
		Now:         func() time.Time { return now },
	})

	reg.SetAlias(ip, "Living Room Fire TV")

	hdrs := http.Header{}
	hdrs.Set("x-proxide-client", "controller-a")
	hdrs.Set("User-Agent", "AmazonWebAppPlatform")

	id := reg.Resolve(context.Background(), "[::ffff:192.168.1.77]:49001", hdrs, model.PlatformFireTV)
	if id.IP != ip {
		t.Fatalf("got IP %v, want %v", id.IP, ip)
	}
	if id.Tag != "controller-a" {
		t.Fatalf("got tag %q, want controller-a", id.Tag)
	}
	if hdrs.Get("X-Proxide-Client") != "" {
		t.Fatal("expected X-Proxide-Client header to be stripped after extraction")
	}
	if id.FriendlyName != "Living Room Fire TV" {
		t.Fatalf("got alias %q", id.FriendlyName)
	}
	if id.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("got MAC %q", id.MAC)
	}
	if id.Platform != model.PlatformFireTV {
		t.Fatalf("got platform %s", id.Platform)
	}

	records := reg.List()
	if len(records) != 1 || records[0].FlowCount != 1 {
		t.Fatalf("unexpected client records: %+v", records)
	}
}

func TestParseARPOutputHandlesMacOSAndIncompleteEntries(t *testing.T) {
	t.Parallel()
	raw := `
? (192.168.1.1) at a:b:cc:d:ee:1 on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.99) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
`
	parsed := ParseARPOutput(raw)
	if got := parsed[netip.MustParseAddr("192.168.1.1")]; got != "0a:0b:cc:0d:ee:01" {
		t.Fatalf("got %q, want zero-padded MAC", got)
	}
	if _, exists := parsed[netip.MustParseAddr("192.168.1.50")]; exists {
		t.Fatal("did not expect incomplete entry in ARP map")
	}
	if got := parsed[netip.MustParseAddr("192.168.1.99")]; got != "11:22:33:44:55:66" {
		t.Fatalf("got %q", got)
	}
}
