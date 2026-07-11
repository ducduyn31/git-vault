// Package local implements git-vault's first real key Provider: a
// single-machine key backed by a locally generated age identity. It is
// not a team key-sharing solution — the private key never leaves the
// machine it was generated on. It doubles as internal/vault's own
// integration-test fixture, proving the sops <-> keyservice <-> Provider
// pipeline end-to-end without needing a real SSO provider built first.
package local

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Name is the provider name used in "local:<recipient>" key identifiers
// (see internal/keyservice.Server).
const Name = "local"

// Provider is a Provider backed by a locally generated X25519 age
// identity persisted at IdentityPath.
type Provider struct {
	IdentityPath string
}

// New returns a Provider using the default identity path (see
// DefaultIdentityPath). The identity itself is not generated until
// Recipient, Encrypt, or Decrypt is first called.
func New() (*Provider, error) {
	path, err := DefaultIdentityPath()
	if err != nil {
		return nil, err
	}
	return &Provider{IdentityPath: path}, nil
}

// DefaultIdentityPath returns ~/.cache/git-vault/local/identity.txt
// (honoring $XDG_CACHE_HOME on Linux via os.UserCacheDir).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "local", "identity.txt"), nil
}

// Name identifies this provider in a "local:<key-id>" identifier.
func (p *Provider) Name() string { return Name }

// Recipient returns this provider's current recipient key-id — a bech32
// age public key — generating and persisting a new identity on first
// use.
func (p *Provider) Recipient() (string, error) {
	id, err := p.identity()
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// Encrypt encrypts plaintext (a sops data key) to the recipient named by
// keyID using real age encryption, armored (see armor.NewWriter below) so
// the result is safe to store as a string inside a YAML/JSON document —
// raw binary age output is not valid UTF-8 and JSON in particular would
// silently corrupt it.
func (p *Provider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(keyID)
	if err != nil {
		return nil, fmt.Errorf("local: parse recipient %q: %w", keyID, err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored ciphertext (see Encrypt) using this provider's
// persisted identity. keyID is not consulted — a Provider only ever holds
// one identity.
func (p *Provider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	id, err := p.identity()
	if err != nil {
		return nil, err
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, id)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	return plaintext, nil
}

// identity loads the identity persisted at p.IdentityPath, generating and
// persisting a new one if none exists yet.
func (p *Provider) identity() (*age.X25519Identity, error) {
	data, err := os.ReadFile(p.IdentityPath)
	if err == nil {
		id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("local: parse identity: %w", err)
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("local: read identity: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("local: generate identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
		return nil, fmt.Errorf("local: create identity dir: %w", err)
	}
	if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("local: write identity: %w", err)
	}
	return id, nil
}
