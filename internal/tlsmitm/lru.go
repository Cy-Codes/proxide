package tlsmitm

import (
	"container/list"
	"crypto/tls"
	"sync"
	"time"
)

type cachedLeaf struct {
	key       string
	cert      *tls.Certificate
	serial    string
	expiresAt time.Time
}

type certLRU struct {
	mu            sync.Mutex
	capacity      int
	refreshMargin time.Duration
	ll            *list.List
	items         map[string]*list.Element
}

func newCertLRU(capacity int, refreshMargin time.Duration) *certLRU {
	if capacity <= 0 {
		capacity = 1
	}
	return &certLRU{
		capacity:      capacity,
		refreshMargin: refreshMargin,
		ll:            list.New(),
		items:         make(map[string]*list.Element, capacity),
	}
}

func (c *certLRU) Get(host string, now time.Time) (*tls.Certificate, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[host]
	if !ok {
		return nil, "", false
	}
	entry := elem.Value.(cachedLeaf)
	if !now.Before(entry.expiresAt.Add(-c.refreshMargin)) {
		c.ll.Remove(elem)
		delete(c.items, host)
		return nil, "", false
	}
	c.ll.MoveToFront(elem)
	return entry.cert, entry.serial, true
}

func (c *certLRU) Put(host string, cert *tls.Certificate, serial string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[host]; ok {
		c.ll.MoveToFront(elem)
		elem.Value = cachedLeaf{
			key:       host,
			cert:      cert,
			serial:    serial,
			expiresAt: expiresAt,
		}
		return
	}

	elem := c.ll.PushFront(cachedLeaf{
		key:       host,
		cert:      cert,
		serial:    serial,
		expiresAt: expiresAt,
	})
	c.items[host] = elem

	if c.ll.Len() > c.capacity {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			oldEntry := oldest.Value.(cachedLeaf)
			delete(c.items, oldEntry.key)
		}
	}
}

func (c *certLRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
