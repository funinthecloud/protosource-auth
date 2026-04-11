package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/funinthecloud/protosource-auth/service"
)

func TestMapDirectoryAddFind(t *testing.T) {
	d := service.NewMapDirectory()
	d.Add("alice@example.com", "user-alice")

	id, err := d.FindByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if id != "user-alice" {
		t.Errorf("id = %q, want user-alice", id)
	}
}

func TestMapDirectoryMissingReturnsSentinel(t *testing.T) {
	d := service.NewMapDirectory()
	_, err := d.FindByEmail(context.Background(), "bob@example.com")
	if !errors.Is(err, service.ErrDirectoryNotFound) {
		t.Errorf("FindByEmail(missing) = %v, want ErrDirectoryNotFound", err)
	}
}

func TestMapDirectoryAddOverwrites(t *testing.T) {
	d := service.NewMapDirectory()
	d.Add("alice@example.com", "user-alice")
	d.Add("alice@example.com", "user-alice-2")

	id, _ := d.FindByEmail(context.Background(), "alice@example.com")
	if id != "user-alice-2" {
		t.Errorf("id = %q, want user-alice-2 (second Add should overwrite)", id)
	}
}

func TestMapDirectoryRemove(t *testing.T) {
	d := service.NewMapDirectory()
	d.Add("alice@example.com", "user-alice")
	d.Remove("alice@example.com")
	_, err := d.FindByEmail(context.Background(), "alice@example.com")
	if !errors.Is(err, service.ErrDirectoryNotFound) {
		t.Errorf("after Remove, FindByEmail = %v, want ErrDirectoryNotFound", err)
	}
	// Removing a missing entry must not panic.
	d.Remove("nobody@example.com")
}

func TestMapDirectoryConcurrent(t *testing.T) {
	d := service.NewMapDirectory()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d.Add("a@x", "u")
			_, _ = d.FindByEmail(context.Background(), "a@x")
			d.Len()
		}(i)
	}
	wg.Wait()
}
