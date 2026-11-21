package tlsmitm

import "sync"

type sfCall[V any] struct {
	wg  sync.WaitGroup
	val V
	err error
}

// singleflightGroup deduplicates concurrent work per key using pure Go stdlib primitives.
type singleflightGroup[K comparable, V any] struct {
	mu    sync.Mutex
	calls map[K]*sfCall[V]
}

func (g *singleflightGroup[K, V]) Do(key K, fn func() (V, error)) (V, error, bool) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[K]*sfCall[V])
	}
	if existing, ok := g.calls[key]; ok {
		g.mu.Unlock()
		existing.wg.Wait()
		return existing.val, existing.err, true
	}

	call := &sfCall[V]{}
	call.wg.Add(1)
	g.calls[key] = call
	g.mu.Unlock()

	func() {
		defer func() {
			g.mu.Lock()
			delete(g.calls, key)
			g.mu.Unlock()
			call.wg.Done()
		}()
		call.val, call.err = fn()
	}()

	return call.val, call.err, false
}
