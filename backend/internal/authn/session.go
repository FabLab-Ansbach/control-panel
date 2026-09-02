package authn

import (
	"sync"
	"time"
)

// sessionStore is an in-memory session table. Sessions don't survive a
// restart and aren't shared across instances — fine for a single-process
// hobby deployment. Expired entries are evicted lazily on read.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	groups    []string
	user      string
	expiresAt time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]session)}
}

func (s *sessionStore) create(groups []string, user string, ttl time.Duration) string {
	id := randomID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session{groups: groups, user: user, expiresAt: time.Now().Add(ttl)}
	return id
}

func (s *sessionStore) get(id string) ([]string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, "", false
	}
	if time.Now().After(sess.expiresAt) {
		delete(s.sessions, id)
		return nil, "", false
	}
	return sess.groups, sess.user, true
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
