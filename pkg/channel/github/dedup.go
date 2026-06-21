package github

import "sync"

// deliveryCache de-duplicates webhook deliveries by their X-GitHub-Delivery
// id (ADR 0008): GitHub may redeliver the same event, and one PR event must
// not trigger redundant work. An id is reserved before processing and only
// committed on success, so a delivery that failed can still be retried.
//
// Committed ids are bounded by a FIFO ring so memory does not grow without
// limit on a long-running daemon.
type deliveryCache struct {
	mu       sync.Mutex
	inFlight map[string]struct{}
	done     map[string]struct{}
	order    []string
	cap      int
}

func newDeliveryCache(capacity int) *deliveryCache {
	if capacity <= 0 {
		capacity = 1024
	}
	return &deliveryCache{
		inFlight: map[string]struct{}{},
		done:     map[string]struct{}{},
		cap:      capacity,
	}
}

// reserve claims id for processing. It returns false if the id is already
// committed or in flight (a duplicate), true if the caller now owns it.
func (c *deliveryCache) reserve(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.done[id]; ok {
		return false
	}
	if _, ok := c.inFlight[id]; ok {
		return false
	}
	c.inFlight[id] = struct{}{}
	return true
}

// commit marks a reserved id as fully handled.
func (c *deliveryCache) commit(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inFlight, id)
	if _, ok := c.done[id]; ok {
		return
	}
	c.done[id] = struct{}{}
	c.order = append(c.order, id)
	if len(c.order) > c.cap {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.done, evict)
	}
}

// release abandons a reserved id so the delivery can be retried.
func (c *deliveryCache) release(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inFlight, id)
}
