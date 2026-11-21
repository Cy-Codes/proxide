package bus

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"proxide/internal/model"
)

func TestBusNonBlockingDropAndCleanShutdown(t *testing.T) {
	t.Parallel()
	b := NewBus(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, unsub := b.Subscribe(ctx, EventFilter{ClientTag: "ctrl-a"})
	defer unsub()

	// Publish 10 matching events without reading; Publish must never block.
	for i := range 10 {
		b.Publish(model.CaptureEvent{
			ID:        fmt.Sprintf("flow-%02d", i),
			Timestamp: time.Now().UTC(),
			Client: model.ClientIdentity{
				IP:  netip.MustParseAddr("192.168.1.10"),
				Tag: "ctrl-a",
			},
			Protocol: model.ProtocolHTTPS,
		})
	}

	// Non-matching event should be filtered out.
	b.Publish(model.CaptureEvent{
		ID:       "flow-other",
		Client:   model.ClientIdentity{IP: netip.MustParseAddr("192.168.1.11"), Tag: "ctrl-b"},
		Protocol: model.ProtocolHTTP,
	})

	stats := b.Stats()
	if stats.PublishedTotal != 11 {
		t.Fatalf("published = %d, want 11", stats.PublishedTotal)
	}
	if stats.DroppedTotal == 0 {
		t.Fatal("expected dropped > 0 for saturated subscriber queue")
	}

	b.Close()
	received := 0
	for ev := range ch {
		received++
		if ev.Client.Tag != "ctrl-a" {
			t.Fatalf("unexpected filtered event: %+v", ev)
		}
	}
	if received != 2 {
		t.Fatalf("expected 2 buffered events before close, got %d", received)
	}
}

func TestRingStoreDualBoundsAndNewestFirstList(t *testing.T) {
	t.Parallel()
	store := NewRingStore(3, 1024*1024)

	for i := range 5 {
		store.Append(model.CaptureEvent{
			ID:        fmt.Sprintf("flow-%d", i),
			Timestamp: time.Now().UTC(),
			Client:    model.ClientIdentity{IP: netip.MustParseAddr("192.168.1.20")},
			Protocol:  model.ProtocolHTTP,
			Request:   &model.HTTPRequestSnapshot{Method: "GET", Host: "api.example.com"},
			Response:  &model.HTTPResponseSnapshot{Status: 200},
		})
	}

	stats := store.Stats()
	if stats.Flows != 3 || stats.EvictedTotal != 2 {
		t.Fatalf("unexpected flow count stats: %+v", stats)
	}

	list := store.List(FlowFilter{Limit: 10})
	if len(list) != 3 || list[0].ID != "flow-4" || list[2].ID != "flow-2" {
		t.Fatalf("unexpected newest-first ordering: %+v", list)
	}

	// Byte-budget eviction check with tight cap.
	byteStore := NewRingStore(100, 1200)
	bigPayload := strings.Repeat("a", 500)
	for i := range 4 {
		byteStore.Append(model.CaptureEvent{
			ID:       fmt.Sprintf("big-%d", i),
			Protocol: model.ProtocolHTTP,
			Response: &model.HTTPResponseSnapshot{Status: 200, BodyPreview: bigPayload},
		})
	}
	bStats := byteStore.Stats()
	if bStats.ApproxBytes > 1200 || bStats.Flows >= 4 {
		t.Fatalf("expected byte-budget eviction to cap store <= 1200 bytes, got: %+v", bStats)
	}
}
