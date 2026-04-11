package service

import (
	"context"
	"errors"
	"sync"
)

// ErrDirectoryNotFound is returned by [MapDirectory.FindByEmail] when
// the email is not present. The Loginer maps any lookup error to
// ErrInvalidCredentials, so the concrete sentinel matters mostly for
// testing and for other directory implementations that want to
// distinguish "not found" from "lookup failed".
var ErrDirectoryNotFound = errors.New("service: directory entry not found")

// MapDirectory is an in-memory email→user-id [UserDirectory]. It is
// the default directory used by the memorystore-backed runnable binary:
// startup bootstrap adds its admin user, and the service repopulates on
// every process restart.
//
// Production deployments that store User aggregates in DynamoDB (or any
// backend with GSI support) should instead provide a UserDirectory that
// runs a GSI query against the generated UserClient.
//
// Safe for concurrent use.
type MapDirectory struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewMapDirectory returns an empty, thread-safe MapDirectory.
func NewMapDirectory() *MapDirectory {
	return &MapDirectory{data: make(map[string]string)}
}

// Add registers an email→user-id mapping, overwriting any previous
// entry for the same email.
func (d *MapDirectory) Add(email, userID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[email] = userID
}

// Remove deletes an email's mapping. A no-op if the email is missing.
func (d *MapDirectory) Remove(email string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.data, email)
}

// Len returns the number of entries. Intended for tests and diagnostics.
func (d *MapDirectory) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.data)
}

// FindByEmail satisfies [UserDirectory]. It returns the registered user
// id for email, or ErrDirectoryNotFound if none is present.
func (d *MapDirectory) FindByEmail(_ context.Context, email string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.data[email]
	if !ok {
		return "", ErrDirectoryNotFound
	}
	return id, nil
}

// Compile-time assertion.
var _ UserDirectory = (*MapDirectory)(nil)
