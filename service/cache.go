package service

import (
	"sync"
	"time"
)

// DefaultFunctionCacheTTL is the default staleness window for the
// user→function-set cache used by [Checker]. Increase for lower store
// pressure at the cost of slower role-change propagation; decrease for
// faster propagation at the cost of more Loads per check.
const DefaultFunctionCacheTTL = 60 * time.Second

// functionCache maps a user id to the union of function strings granted
// by that user's currently-assigned roles, with a TTL-based staleness
// bound. It is intentionally not an LRU — the active-user keyspace for a
// given process is bounded, so entries fall out via TTL alone.
//
// Safe for concurrent use.
type functionCache struct {
	ttl   time.Duration
	clock func() time.Time

	mu   sync.Mutex
	data map[string]functionCacheEntry
}

type functionCacheEntry struct {
	functions []string
	expiresAt time.Time
}

func newFunctionCache(ttl time.Duration, clock func() time.Time) *functionCache {
	if clock == nil {
		clock = time.Now
	}
	return &functionCache{
		ttl:   ttl,
		clock: clock,
		data:  make(map[string]functionCacheEntry),
	}
}

// get returns the cached function set for userID if it is present and
// has not yet expired. On miss or expiry it returns (nil, false) so the
// caller can repopulate.
func (c *functionCache) get(userID string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[userID]
	if !ok {
		return nil, false
	}
	if !c.clock().Before(e.expiresAt) {
		// Expired — evict proactively so a later put doesn't race with a
		// concurrent reader holding a stale slice.
		delete(c.data, userID)
		return nil, false
	}
	return e.functions, true
}

// put stores functions under userID with a fresh TTL window. Callers
// should pass an already-computed union (the cache does not merge).
func (c *functionCache) put(userID string, functions []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[userID] = functionCacheEntry{
		functions: functions,
		expiresAt: c.clock().Add(c.ttl),
	}
}

// invalidate removes userID's entry regardless of TTL. Intended for
// hand-written hooks that want to force a refresh after they know a
// role change landed.
func (c *functionCache) invalidate(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, userID)
}
