package auth

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"
)

// memStore is an in-memory Store for tests.
type memStore struct {
	mu         sync.Mutex
	nextID     int64
	sessions   map[int64]Session
	identities map[[2]string]IdentityLink
	passwords  map[int64]PasswordRecord
	links      map[string]memLink
}

type memLink struct {
	userID  int64
	expires time.Time
}

func newMemStore() *memStore {
	return &memStore{
		sessions:   map[int64]Session{},
		identities: map[[2]string]IdentityLink{},
		passwords:  map[int64]PasswordRecord{},
		links:      map[string]memLink{},
	}
}

var _ Store = (*memStore)(nil)

func (m *memStore) CreateSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s.ID = m.nextID
	m.sessions[s.ID] = *s
	return nil
}

func (m *memStore) GetSession(_ context.Context, h []byte, now time.Time) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if bytes.Equal(s.TokenHash, h) && s.ExpiresAt.After(now) {
			return s, nil
		}
	}
	return Session{}, ErrNotFound
}

func (m *memStore) TouchSession(_ context.Context, id int64, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.LastUsedAt = t
		m.sessions[id] = s
	}
	return nil
}

func (m *memStore) DeleteSessionByHash(_ context.Context, h []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if bytes.Equal(s.TokenHash, h) {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *memStore) DeleteSession(_ context.Context, userID, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.UserID != userID {
		return ErrNotFound
	}
	delete(m.sessions, id)
	return nil
}

func (m *memStore) DeleteUserSessions(_ context.Context, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *memStore) DeleteExpiredSessions(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *memStore) ListSessions(_ context.Context, userID int64, now time.Time) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Session
	for _, s := range m.sessions {
		if s.UserID == userID && s.ExpiresAt.After(now) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *memStore) GetIdentity(_ context.Context, iss, sub string) (IdentityLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.identities[[2]string{iss, sub}]
	if !ok {
		return IdentityLink{}, ErrNotFound
	}
	return l, nil
}

func (m *memStore) CreateIdentity(_ context.Context, l IdentityLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{l.Issuer, l.Subject}
	if _, ok := m.identities[k]; ok {
		return ErrExists
	}
	m.identities[k] = l
	return nil
}

func (m *memStore) UserHasIdentity(_ context.Context, userID int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.identities {
		if l.UserID == userID {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) ListIdentities(_ context.Context, userID int64) ([]IdentityLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []IdentityLink
	for _, l := range m.identities {
		if l.UserID == userID {
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *memStore) DeleteIdentity(_ context.Context, userID int64, iss, sub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{iss, sub}
	if l, ok := m.identities[k]; !ok || l.UserID != userID {
		return ErrNotFound
	}
	delete(m.identities, k)
	return nil
}

func (m *memStore) CreateOIDCLink(_ context.Context, h []byte, userID int64, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[string(h)] = memLink{userID: userID, expires: exp}
	return nil
}

func (m *memStore) ConsumeOIDCLink(_ context.Context, h []byte, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[string(h)]
	delete(m.links, string(h))
	if !ok || !l.expires.After(now) {
		return 0, ErrNotFound
	}
	return l.userID, nil
}

func (m *memStore) GetPasswordByUsername(_ context.Context, u string) (PasswordRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.passwords {
		if strings.EqualFold(r.Username, u) {
			return r, nil
		}
	}
	return PasswordRecord{}, ErrNotFound
}

func (m *memStore) GetPasswordByUserID(_ context.Context, userID int64) (PasswordRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.passwords[userID]
	if !ok {
		return PasswordRecord{}, ErrNotFound
	}
	return r, nil
}

func (m *memStore) CreatePassword(_ context.Context, r PasswordRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.passwords[r.UserID]; ok {
		return ErrExists
	}
	for _, o := range m.passwords {
		if strings.EqualFold(o.Username, r.Username) {
			return ErrExists
		}
	}
	m.passwords[r.UserID] = r
	return nil
}

func (m *memStore) UpdatePasswordHash(_ context.Context, userID int64, h string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.passwords[userID]
	if !ok {
		return ErrNotFound
	}
	r.Hash = h
	m.passwords[userID] = r
	return nil
}

func (m *memStore) RecordLoginFailure(_ context.Context, userID int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.passwords[userID]; ok {
		r.FailedAttempts++
		r.LastFailedAt = at
		m.passwords[userID] = r
	}
	return nil
}

func (m *memStore) ResetLoginFailures(_ context.Context, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.passwords[userID]; ok {
		r.FailedAttempts = 0
		r.LastFailedAt = time.Time{}
		m.passwords[userID] = r
	}
	return nil
}

func (m *memStore) DeleteUser(_ context.Context, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, id)
		}
	}
	for k, l := range m.identities {
		if l.UserID == userID {
			delete(m.identities, k)
		}
	}
	delete(m.passwords, userID)
	for k, l := range m.links {
		if l.userID == userID {
			delete(m.links, k)
		}
	}
	return nil
}
