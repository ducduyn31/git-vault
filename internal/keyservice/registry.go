package keyservice

import (
	"fmt"
	"sync"
)

// Registry looks up a Provider by name. It is safe for concurrent use.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register adds p to the registry under p.Name(). It errors if a provider
// with that name is already registered.
func (r *Registry) Register(p Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[p.Name()]; exists {
		return fmt.Errorf("keyservice: provider %q already registered", p.Name())
	}
	r.providers[p.Name()] = p
	return nil
}

// Get returns the provider registered under name, if any.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	return p, ok
}
