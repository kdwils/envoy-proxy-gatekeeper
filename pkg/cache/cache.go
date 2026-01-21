package cache

import (
	"context"
	"sync"
	"time"
)

type CleanupFunc[K comparable, V any] func(key K, value V) bool

type Cache[K comparable, T any] struct {
	mu              sync.RWMutex
	entries         map[K]T
	cleanupInterval time.Duration
	cleanupFunc     CleanupFunc[K, T]
}

type Option[K comparable, T any] func(*Cache[K, T])

func New[K comparable, T any](opts ...Option[K, T]) *Cache[K, T] {
	c := &Cache[K, T]{
		mu:      sync.RWMutex{},
		entries: make(map[K]T),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func WithCleanup[K comparable, T any](interval time.Duration, cleanupFunc CleanupFunc[K, T]) Option[K, T] {
	return func(c *Cache[K, T]) {
		c.cleanupInterval = interval
		c.cleanupFunc = cleanupFunc
	}
}

func (c *Cache[K, T]) Set(key K, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = value
}

func (c *Cache[K, T]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *Cache[K, T]) Get(key K) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	return entry, ok
}

func (c *Cache[K, T]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache[K, T]) Keys() []K {
	keys := make([]K, len(c.entries))
	i := 0
	for k := range c.entries {
		keys[i] = k
		i++
	}

	return keys
}

func (c *Cache[K, T]) StartCleanup(ctx context.Context) {
	if c.cleanupInterval == 0 || c.cleanupFunc == nil {
		return
	}

	ticker := time.NewTicker(c.cleanupInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				var keysToDelete []K

				c.mu.RLock()
				for key, value := range c.entries {
					if c.cleanupFunc(key, value) {
						keysToDelete = append(keysToDelete, key)
					}
				}
				c.mu.RUnlock()

				if len(keysToDelete) > 0 {
					c.mu.Lock()
					for _, key := range keysToDelete {
						delete(c.entries, key)
					}
					c.mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *Cache[K, T]) Cleanup(ctx context.Context, shouldDelete func(key K, value T) bool) {
	if c.cleanupInterval == 0 {
		return
	}

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var keysToDelete []K

			c.mu.RLock()
			for key, value := range c.entries {
				if shouldDelete(key, value) {
					keysToDelete = append(keysToDelete, key)
				}
			}
			c.mu.RUnlock()

			if len(keysToDelete) > 0 {
				c.mu.Lock()
				for _, key := range keysToDelete {
					delete(c.entries, key)
				}
				c.mu.Unlock()
			}
		case <-ctx.Done():
			return
		}
	}
}
