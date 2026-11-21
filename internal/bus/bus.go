package bus

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"proxide/internal/config"
	"proxide/internal/model"
)

// Publisher emits immutable capture events to all active subscribers.
type Publisher interface {
	Publish(evt model.CaptureEvent)
}

// EventFilter narrows streamed CaptureEvent deliveries by client or host.
type EventFilter struct {
	ClientIP  netip.Addr
	ClientTag string
	Host      string
	Method    string
}

// Matches reports whether evt satisfies all non-empty filter criteria.
func (f EventFilter) Matches(evt model.CaptureEvent) bool {
	if f.ClientIP.IsValid() && evt.Client.IP.Unmap() != f.ClientIP.Unmap() {
		return false
	}
	if f.ClientTag != "" && evt.Client.Tag != f.ClientTag {
		return false
	}
	if f.Method != "" {
		if evt.Request == nil || !strings.EqualFold(evt.Request.Method, f.Method) {
			return false
		}
	}
	if f.Host != "" {
		host := ""
		if evt.Request != nil {
			host = evt.Request.Host
		} else if evt.TLS != nil {
			host = evt.TLS.SNI
		}
		if !strings.Contains(strings.ToLower(host), strings.ToLower(strings.TrimSpace(f.Host))) {
			return false
		}
	}
	return true
}

// BusStats summarizes live event bus metrics.
type BusStats struct {
	ActiveSubscribers int    `json:"active_subscribers"`
	PublishedTotal    uint64 `json:"published_total"`
	DroppedTotal      uint64 `json:"dropped_total"`
}

// Subscriber manages live event subscriptions for inspectors and streams.
type Subscriber interface {
	Subscribe(ctx context.Context, filter EventFilter) (<-chan model.CaptureEvent, func())
	Stats() BusStats
}

type subscriber struct {
	id        uint64
	ch        chan model.CaptureEvent
	filter    EventFilter
	closeOnce sync.Once
}

func (s *subscriber) closeChannel() {
	s.closeOnce.Do(func() {
		close(s.ch)
	})
}

// Bus is a non-blocking, thread-safe pub/sub dispatcher for CaptureEvents.
type Bus struct {
	queueSize int
	mu        sync.RWMutex
	closed    bool
	nextID    uint64
	subs      map[uint64]*subscriber
	published atomic.Uint64
	dropped   atomic.Uint64
}

// NewBus constructs a non-blocking Bus with per-subscriber bounded queues.
func NewBus(queueSize int) *Bus {
	if queueSize <= 0 {
		queueSize = config.DefaultSubscriberQueueSize
	}
	return &Bus{
		queueSize: queueSize,
		subs:      make(map[uint64]*subscriber),
	}
}

// Publish fans out evt non-blockingly to matching subscribers, dropping excess events when a subscriber lags.
func (b *Bus) Publish(evt model.CaptureEvent) {
	b.published.Add(1)
	cloned := evt.Clone()

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}
	for _, sub := range b.subs {
		if !sub.filter.Matches(cloned) {
			continue
		}
		evCopy := cloned.Clone()
		select {
		case sub.ch <- evCopy:
		default:
			// Evict one older queued item on saturation so newest telemetry remains observable without blocking.
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- evCopy:
			default:
			}
			b.dropped.Add(1)
		}
	}
}

// Subscribe registers a bounded channel subscription canceled automatically when ctx ends or cancel is called.
func (b *Bus) Subscribe(ctx context.Context, filter EventFilter) (<-chan model.CaptureEvent, func()) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		ch := make(chan model.CaptureEvent)
		close(ch)
		return ch, func() {}
	}

	b.nextID++
	id := b.nextID
	sub := &subscriber{
		id:     id,
		ch:     make(chan model.CaptureEvent, b.queueSize),
		filter: filter,
	}
	b.subs[id] = sub
	b.mu.Unlock()

	var unsubOnce sync.Once
	cancel := func() {
		unsubOnce.Do(func() {
			b.mu.Lock()
			removed, ok := b.subs[id]
			if ok {
				delete(b.subs, id)
			}
			b.mu.Unlock()
			if ok {
				removed.closeChannel()
			}
		})
	}

	if ctx != nil {
		go func() {
			<-ctx.Done()
			cancel()
		}()
	}

	return sub.ch, cancel
}

// Close terminates all active subscriber channels deterministically during daemon shutdown.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	toClose := make([]*subscriber, 0, len(b.subs))
	for _, sub := range b.subs {
		toClose = append(toClose, sub)
	}
	clear(b.subs)
	b.mu.Unlock()

	for _, sub := range toClose {
		sub.closeChannel()
	}
}

// Stats returns atomic bus subscriber, publish, and drop counters.
func (b *Bus) Stats() BusStats {
	b.mu.RLock()
	active := len(b.subs)
	b.mu.RUnlock()
	return BusStats{
		ActiveSubscribers: active,
		PublishedTotal:    b.published.Load(),
		DroppedTotal:      b.dropped.Load(),
	}
}
