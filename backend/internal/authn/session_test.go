package authn

import (
	"testing"
	"time"
)

func TestSessionStore(t *testing.T) {
	store := newSessionStore()

	id := store.create([]string{"admins"}, "alice", time.Minute)
	groups, user, ok := store.get(id)
	if !ok || len(groups) != 1 || groups[0] != "admins" || user != "alice" {
		t.Fatalf("get() = %v, %v, %v; want [admins], alice, true", groups, user, ok)
	}

	if _, _, ok := store.get("nonexistent"); ok {
		t.Fatal("get() of unknown id should fail")
	}

	expired := store.create([]string{"admins"}, "alice", -time.Second)
	if _, _, ok := store.get(expired); ok {
		t.Fatal("get() of expired session should fail")
	}

	store.delete(id)
	if _, _, ok := store.get(id); ok {
		t.Fatal("get() after delete should fail")
	}
}
