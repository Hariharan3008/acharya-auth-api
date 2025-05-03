package storage

import (
	  "acharya-auth-api/errors"
      "sync"
)

type User interface {
	Exists(email string) bool
	Get(email string) (string, error)
	Save(email, password string)
}

type Token interface {
	Save(accessToken, refreshToken string)
	Exists(accessToken string) bool
	GetByRefresh(refreshToken string) (string, bool)
	Revoke(accessToken string)
}

type Users struct {
	users map[string]string
	mu    sync.RWMutex
}

func NewUser() *Users {
	return &Users{
		users: make(map[string]string),
	}
}

func (s *Users) Exists(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.users[email]
	return exists
}

func (s *Users) Get(email string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pass, exists := s.users[email]
	if !exists {
		return "", errors.ErrUserNotFound
	}
	return pass, nil
}

func (s *Users) Save(email, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[email] = password
}

type Tokens struct {
	accessToRefresh map[string]string  
	refreshToAccess map[string]string  
	revoked         map[string]bool    
	mu              sync.RWMutex
}

func NewToken() *Tokens {
	return &Tokens{
		accessToRefresh: make(map[string]string),
		refreshToAccess: make(map[string]string),
		revoked:         make(map[string]bool),
	}
}

func (s *Tokens) Save(accessToken, refreshToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToRefresh[accessToken] = refreshToken
	s.refreshToAccess[refreshToken] = accessToken
}

func (s *Tokens) Exists(accessToken string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.accessToRefresh[accessToken]
	return exists && !s.revoked[accessToken]
}

func (s *Tokens) GetByRefresh(refreshToken string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	access, exists := s.refreshToAccess[refreshToken]
	return access, exists
}

func (s *Tokens) Revoke(accessToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[accessToken] = true
	delete(s.accessToRefresh, accessToken)
}