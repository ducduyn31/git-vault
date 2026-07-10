// Package session reads and writes git-vault's local session cache
// (~/.cache/git-vault/session.json). Not every Provider needs a session
// (e.g. a KMS-backed provider might use ambient cloud credentials
// instead) — this package is used by whichever providers need it, it is
// not a requirement of the Provider interface itself.
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Session is a cached, short-lived credential for a key Provider.
type Session struct {
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session has expired as of now.
func (s Session) Expired(now time.Time) bool {
	return !s.ExpiresAt.After(now)
}

// DefaultPath returns the default session cache file path,
// ~/.cache/git-vault/session.json (honoring $XDG_CACHE_HOME on Linux via
// os.UserCacheDir).
func DefaultPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "session.json"), nil
}

// Load reads and parses the session file at path.
func Load(path string) (Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, err
	}
	return s, nil
}

// Save writes s to path, creating parent directories as needed. The file
// is written with 0600 permissions since it holds credential material.
func Save(path string, s Session) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
