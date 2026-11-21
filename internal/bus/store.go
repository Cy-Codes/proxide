package bus

import (
	"container/list"
	"net/netip"
	"sync"

	"proxide/internal/config"
	"proxide/internal/model"
)

const minEventByteWeight = 256

// FlowFilter controls read-only flow queries against the capture ring buffer.
type FlowFilter struct {
	ClientIP  netip.Addr
	ClientTag string
	Host      string
	Method    string
	Status    int
	Limit     int
	CursorID  string
}

// StoreStats reports bounded capture ring-buffer utilization.
type StoreStats struct {
	Flows        int   `json:"flows"`
	ApproxBytes  int64 `json:"approx_bytes"`
	MaxFlows     int   `json:"max_flows"`
	MaxBytes     int64 `json:"max_bytes"`
	EvictedTotal int64 `json:"evicted_total"`
}

// FlowStore abstracts bounded capture storage for the loopback inspection API.
type FlowStore interface {
	Append(evt model.CaptureEvent)
	List(filter FlowFilter) []model.CaptureEvent
	Get(id string) (model.CaptureEvent, bool)
	Clear()
	Stats() StoreStats
}

type storedEntry struct {
	event model.CaptureEvent
	bytes int64
}

// RingStore stores up to maxFlows and maxBytes of immutable CaptureEvents in memory.
type RingStore struct {
	mu           sync.RWMutex
	maxFlows     int
	maxBytes     int64
	totalBytes   int64
	evictedTotal int64
	ll           *list.List
	byID         map[string]*list.Element
}

// NewRingStore creates a dual-bounded in-memory ring buffer.
func NewRingStore(maxFlows int, maxBytes int64) *RingStore {
	if maxFlows <= 0 {
		maxFlows = config.DefaultRingBufferFlows
	}
	if maxBytes <= 0 {
		maxBytes = config.DefaultRingBufferMaxBytes
	}
	return &RingStore{
		maxFlows: maxFlows,
		maxBytes: maxBytes,
		ll:       list.New(),
		byID:     make(map[string]*list.Element),
	}
}

// Append stores a defensive clone of evt, evicting oldest entries to honor count and byte limits.
func (s *RingStore) Append(evt model.CaptureEvent) {
	cloned := evt.Clone()
	weight := estimateEventBytes(cloned)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, dup := s.byID[cloned.ID]; dup {
		old := existing.Value.(storedEntry)
		s.totalBytes -= old.bytes
		s.ll.Remove(existing)
		delete(s.byID, cloned.ID)
	}

	for s.ll.Len() > 0 && (s.ll.Len() >= s.maxFlows || s.totalBytes+weight > s.maxBytes) {
		oldest := s.ll.Front()
		if oldest == nil {
			break
		}
		oldEntry := oldest.Value.(storedEntry)
		s.ll.Remove(oldest)
		delete(s.byID, oldEntry.event.ID)
		s.totalBytes -= oldEntry.bytes
		s.evictedTotal++
	}

	elem := s.ll.PushBack(storedEntry{event: cloned, bytes: weight})
	s.byID[cloned.ID] = elem
	s.totalBytes += weight
}

// List returns matching flows ordered newest-first, cloning every returned item.
func (s *RingStore) List(filter FlowFilter) []model.CaptureEvent {
	limit := filter.Limit
	if limit <= 0 || limit > s.maxFlows {
		limit = s.maxFlows
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]model.CaptureEvent, 0)
	cursorPassed := filter.CursorID == ""

	for elem := s.ll.Back(); elem != nil; elem = elem.Prev() {
		ev := elem.Value.(storedEntry).event
		if !cursorPassed {
			if ev.ID == filter.CursorID {
				cursorPassed = true
			}
			continue
		}
		if !matchesFlowFilter(ev, filter) {
			continue
		}
		out = append(out, ev.Clone())
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Get retrieves a defensive clone of a single captured flow by ID.
func (s *RingStore) Get(id string) (model.CaptureEvent, bool) {
	s.mu.RLock()
	elem, ok := s.byID[id]
	if !ok {
		s.mu.RUnlock()
		return model.CaptureEvent{}, false
	}
	ev := elem.Value.(storedEntry).event.Clone()
	s.mu.RUnlock()
	return ev, true
}

// Clear empties all retained flows from the ring store.
func (s *RingStore) Clear() {
	s.mu.Lock()
	s.ll.Init()
	clear(s.byID)
	s.totalBytes = 0
	s.mu.Unlock()
}

// Stats returns current utilization metrics for the ring buffer.
func (s *RingStore) Stats() StoreStats {
	s.mu.RLock()
	stats := StoreStats{
		Flows:        s.ll.Len(),
		ApproxBytes:  s.totalBytes,
		MaxFlows:     s.maxFlows,
		MaxBytes:     s.maxBytes,
		EvictedTotal: s.evictedTotal,
	}
	s.mu.RUnlock()
	return stats
}

func matchesFlowFilter(ev model.CaptureEvent, f FlowFilter) bool {
	ef := EventFilter{
		ClientIP:  f.ClientIP,
		ClientTag: f.ClientTag,
		Host:      f.Host,
		Method:    f.Method,
	}
	if !ef.Matches(ev) {
		return false
	}
	if f.Status > 0 {
		if ev.Response == nil || ev.Response.Status != f.Status {
			return false
		}
	}
	return true
}

func estimateEventBytes(ev model.CaptureEvent) int64 {
	var total int64 = minEventByteWeight
	total += int64(len(ev.ID) + len(ev.Error) + len(ev.Client.Tag) + len(ev.Client.FriendlyName))
	if ev.Request != nil {
		total += int64(len(ev.Request.Method) + len(ev.Request.URL) + len(ev.Request.Host) + len(ev.Request.BodyPreview) + len(ev.Request.BodyBase64))
		for k, vals := range ev.Request.Headers {
			total += int64(len(k))
			for _, v := range vals {
				total += int64(len(v))
			}
		}
	}
	if ev.Response != nil {
		total += int64(len(ev.Response.StatusText) + len(ev.Response.BodyPreview) + len(ev.Response.BodyBase64))
		for k, vals := range ev.Response.Headers {
			total += int64(len(k))
			for _, v := range vals {
				total += int64(len(v))
			}
		}
	}
	for _, fr := range ev.StreamFrames {
		total += int64(len(fr.PayloadPreview) + 64)
	}
	return total
}
