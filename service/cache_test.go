package service

import (
	"sync"
	"testing"
	"time"
)

func TestCacheMissThenHit(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := newFunctionCache(60*time.Second, clock)

	if _, ok := c.get("alice"); ok {
		t.Errorf("expected miss on empty cache")
	}

	c.put("alice", []string{"auth.user.v1.Create", "auth.user.v1.Lock"})
	got, ok := c.get("alice")
	if !ok {
		t.Fatal("expected cache hit after put")
	}
	if len(got) != 2 {
		t.Errorf("cached set = %v, want 2 entries", got)
	}
}

func TestCacheExpiry(t *testing.T) {
	base := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }
	c := newFunctionCache(60*time.Second, clock)

	c.put("alice", []string{"auth.user.v1.Create"})

	// Advance to just before expiry.
	now = base.Add(59 * time.Second)
	if _, ok := c.get("alice"); !ok {
		t.Errorf("cache expired too early")
	}

	// Advance past TTL.
	now = base.Add(61 * time.Second)
	if _, ok := c.get("alice"); ok {
		t.Errorf("cache did not expire")
	}
}

func TestCacheInvalidate(t *testing.T) {
	c := newFunctionCache(60*time.Second, nil)
	c.put("alice", []string{"auth.user.v1.Create"})
	c.invalidate("alice")
	if _, ok := c.get("alice"); ok {
		t.Errorf("invalidate did not remove entry")
	}
	// Invalidating a missing key is a no-op, not a panic.
	c.invalidate("bob")
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := newFunctionCache(60*time.Second, nil)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			userID := "user"
			c.put(userID, []string{"auth.user.v1.Create"})
			_, _ = c.get(userID)
		}(i)
	}
	wg.Wait()
	// The concern is the race detector, not the return values. Run with
	// `go test -race`.
}
