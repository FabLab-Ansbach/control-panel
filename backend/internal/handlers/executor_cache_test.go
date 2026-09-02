package handlers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

type countingExec struct {
	statusCalls  atomic.Int32
	executeCalls atomic.Int32
	state        bool
	err          error
}

func (e *countingExec) Execute(ctx context.Context) (bool, error) {
	e.executeCalls.Add(1)
	e.state = !e.state
	return e.state, e.err
}
func (e *countingExec) Status(ctx context.Context) (bool, error) {
	e.statusCalls.Add(1)
	return e.state, e.err
}
func (e *countingExec) Name() string                    { return "counting" }
func (e *countingExec) Connector() connectors.Connector { return fakeConn{} }

func TestCachedExecutorStatusIsCachedWithinTTL(t *testing.T) {
	underlying := &countingExec{}
	c := newCachedExecutor(underlying)
	c.ttl = 50 * time.Millisecond

	for i := 0; i < 5; i++ {
		if _, err := c.Status(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := underlying.statusCalls.Load(); got != 1 {
		t.Fatalf("underlying Status called %d times, want 1 (should be cached)", got)
	}

	time.Sleep(60 * time.Millisecond)
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := underlying.statusCalls.Load(); got != 2 {
		t.Fatalf("underlying Status called %d times, want 2 (cache should have expired)", got)
	}
}

func TestCachedExecutorExecuteRefreshesCache(t *testing.T) {
	underlying := &countingExec{}
	c := newCachedExecutor(underlying)
	c.ttl = time.Minute // long enough that only Execute should be able to refresh it

	state, err := c.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state {
		t.Fatalf("Execute returned %v, want true", state)
	}

	// Status must reflect Execute's result immediately, without calling the
	// underlying executor again (still within the TTL).
	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatalf("Status = %v, want true (should reflect the just-executed state)", got)
	}
	if calls := underlying.statusCalls.Load(); calls != 0 {
		t.Fatalf("underlying Status called %d times, want 0 (Execute should have populated the cache)", calls)
	}
}

func TestCachedExecutorCachesErrors(t *testing.T) {
	underlying := &countingExec{err: errors.New("network element unreachable")}
	c := newCachedExecutor(underlying)
	c.ttl = time.Minute

	_, err1 := c.Status(context.Background())
	_, err2 := c.Status(context.Background())
	if err1 == nil || err2 == nil {
		t.Fatal("expected cached error to be returned")
	}
	if got := underlying.statusCalls.Load(); got != 1 {
		t.Fatalf("underlying Status called %d times, want 1", got)
	}
}
