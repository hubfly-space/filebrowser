package http

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// ottItem represents an item in the one-time token store.
type ottItem struct {
	jwt     string
	expires time.Time
}

// ottStore is a thread-safe, in-memory store for one-time tokens.
type ottStore struct {
	sync.RWMutex
	items map[string]ottItem
}

// NewOTTStore creates a new one-time token store and starts a cleanup goroutine.
func NewOTTStore() *ottStore {
	s := &ottStore{
		items: make(map[string]ottItem),
	}
	go s.cleaner()
	return s
}

// Set generates a new one-time token, stores the provided JWT with a lifespan, and returns the token.
func (s *ottStore) Set(jwt string, lifespan time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	s.Lock()
	defer s.Unlock()

	s.items[token] = ottItem{
		jwt:     jwt,
		expires: time.Now().Add(lifespan),
	}

	return token, nil
}

// Get retrieves a JWT using a one-time token. It deletes the token after retrieval
// to ensure it's used only once. It returns the JWT and a boolean indicating success.
func (s *ottStore) Get(token string) (string, bool) {
	s.Lock()
	defer s.Unlock()

	item, exists := s.items[token]
	if !exists {
		return "", false
	}

	// Delete the token immediately to ensure one-time use.
	delete(s.items, token)

	if time.Now().After(item.expires) {
		return "", false
	}

	return item.jwt, true
}

// cleaner periodically removes expired tokens from the store.
func (s *ottStore) cleaner() {
	for {
		time.Sleep(1 * time.Minute)

		s.Lock()
		for token, item := range s.items {
			if time.Now().After(item.expires) {
				delete(s.items, token)
			}
		}
		s.Unlock()
	}
}
