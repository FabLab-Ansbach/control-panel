package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/FabLab-Ansbach/control-panel/internal/executors"
)

const statusCacheTTL = 10 * time.Second

// cachedExecutor wraps an Executor so repeated Status polls (the GUI polls
// every 5s) don't hammer the underlying network hardware. Execute always
// runs for real and writes its result straight into the cache, so callers
// see the fresh state immediately instead of waiting out the TTL.
type cachedExecutor struct {
	executors.Executor
	ttl time.Duration

	mu       sync.Mutex
	cachedAt time.Time
	state    bool
	err      error
}

func newCachedExecutor(e executors.Executor) *cachedExecutor {
	return &cachedExecutor{Executor: e, ttl: statusCacheTTL}
}

func (c *cachedExecutor) Status(ctx context.Context) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.cachedAt) < c.ttl {
		return c.state, c.err
	}

	state, err := c.Executor.Status(ctx)
	c.state, c.err, c.cachedAt = state, err, time.Now()
	return state, err
}

func (c *cachedExecutor) Execute(ctx context.Context) (bool, error) {
	state, err := c.Executor.Execute(ctx)

	c.mu.Lock()
	c.state, c.err, c.cachedAt = state, err, time.Now()
	c.mu.Unlock()

	return state, err
}
