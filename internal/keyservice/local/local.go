// Package local implements git-vault's first real key Provider: a
// single-machine key backed by one or more locally generated age
// identities. It is not a team key-sharing solution — private keys never
// leave the machine they were generated on. It doubles as internal/vault's
// own integration-test fixture, proving the sops <-> keyservice <->
// Provider pipeline end-to-end without needing a real SSO provider built
// first.
//
// Identities are stored one per line in IdentityPath, using the same
// format the real `age` CLI's own identity files use (see
// age.ParseIdentities) — newest last. Encrypt always targets the newest
// identity; Decrypt looks up whichever identity's recipient matches the
// keyID a file was actually sealed under, so older identities keep
// decrypting their own ciphertext after a `rotate` (internal/cli) adds a
// new one.
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

// IdentityPathEnvVar overrides the default identities file location (see
// DefaultIdentityPath) when set.
const IdentityPathEnvVar = "GIT_VAULT_LOCAL_IDENTITY_PATH"

// Provider is a Provider backed by one or more locally generated X25519
// age identities persisted at IdentityPath, one per line, newest last.
type Provider struct {
	IdentityPath string
}

// New returns a Provider using IdentityPathEnvVar if set, else the
// default identity path (see DefaultIdentityPath). No identity is
// generated until Recipient, Encrypt, Decrypt, or Rotate is first called.
func New() (*Provider, error) {
	if path := os.Getenv(IdentityPathEnvVar); path != "" {
		return &Provider{IdentityPath: path}, nil
	}
	path, err := DefaultIdentityPath()
	if err != nil {
		return nil, err
	}
	return &Provider{IdentityPath: path}, nil
}

// DefaultIdentityPath returns ~/.cache/git-vault/local/identities
// (honoring $XDG_CACHE_HOME on Linux via os.UserCacheDir).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "local", "identities"), nil
}

func (p *Provider) Name() string { return Name }

// recipientString returns id's bech32 recipient encoding. age.Identity
// doesn't expose Recipient() itself — only the concrete *X25519Identity
// and *HybridIdentity types do, with different return types — so this
// dispatches on the two concrete types local.go supports.
func recipientString(id age.Identity) (string, error) {
	switch v := id.(type) {
	case *age.X25519Identity:
		return v.Recipient().String(), nil
	case *age.HybridIdentity:
		return v.Recipient().String(), nil
	default:
		return "", fmt.Errorf("local: unsupported identity type %T", id)
	}
}

// Recipient returns the newest stored identity's recipient — a bech32
// age public key — generating a first identity if none are stored yet.
func (p *Provider) Recipient() (string, error) {
	ids, err := p.identities()
	if err != nil {
		return "", err
	}
	return recipientString(ids[len(ids)-1])
}

// Rotate generates a fresh identity, appends and durably persists it
// alongside any existing ones (older identities are never removed — they
// stay valid for decrypting anything not yet re-sealed with the new one,
// including already-committed ciphertext), and returns its recipient.
// Persisted before returning, not after some later step, so a process
// that dies right after Rotate still leaves the new key durably on disk.
func (p *Provider) Rotate() (string, error) {
	if _, err := p.identities(); err != nil { // ensures the file/dir exist
		return "", err
	}

	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", fmt.Errorf("local: generate identity: %w", err)
	}
	f, err := os.OpenFile(p.IdentityPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("local: open identities file: %w", err)
	}
	if _, err := f.WriteString(id.String() + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("local: append identity: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("local: close identities file: %w", err)
	}
	return id.Recipient().String(), nil
}

// Encrypt encrypts plaintext (a sops data key) to the recipient named by
// keyID using real age encryption, armored (see armor.NewWriter below) so
// the result is safe to store as a string inside a YAML/JSON document —
// raw binary age output is not valid UTF-8 and JSON in particular would
// silently corrupt it. age.ParseRecipients (rather than a hardcoded
// X25519 parse) dispatches on the age1/age1pq prefix, so this handles
// both classical and hybrid post-quantum recipients.
func (p *Provider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	recipients, err := age.ParseRecipients(strings.NewReader(keyID))
	if err != nil {
		return nil, fmt.Errorf("local: parse recipient %q: %w", keyID, err)
	}
	if len(recipients) != 1 {
		return nil, fmt.Errorf("local: expected exactly one recipient in %q, got %d", keyID, len(recipients))
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients[0])
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

// Decrypt decrypts armored ciphertext (see Encrypt) using whichever
// stored identity's recipient matches keyID — the file's own sops
// metadata already names exactly which identity encrypted it, so this
// looks it up precisely rather than trying every stored identity.
func (p *Provider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	ids, err := p.identities()
	if err != nil {
		return nil, err
	}
	var match age.Identity
	for _, id := range ids {
		s, err := recipientString(id)
		if err != nil {
			return nil, err
		}
		if s == keyID {
			match = id
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("local: no stored identity matches recipient %q", keyID)
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, match)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	return plaintext, nil
}

// identities loads every identity persisted at p.IdentityPath, migrating
// forward a pre-rename identity.txt sibling if one exists (see
// migrateLegacyIdentity), or generating and persisting a single fresh
// identity if neither exists yet. The list may mix *age.X25519Identity
// (pre-PQ) and *age.HybridIdentity (post-PQ) entries — see Rotate.
func (p *Provider) identities() ([]age.Identity, error) {
	data, err := os.ReadFile(p.IdentityPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("local: read identities: %w", err)
		}
		migrated, migrateErr := p.migrateLegacyIdentity()
		if migrateErr != nil {
			return nil, migrateErr
		}
		if !migrated {
			id, err := age.GenerateHybridIdentity()
			if err != nil {
				return nil, fmt.Errorf("local: generate identity: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
				return nil, fmt.Errorf("local: create identity dir: %w", err)
			}
			if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("local: write identities: %w", err)
			}
			return []age.Identity{id}, nil
		}
		data, err = os.ReadFile(p.IdentityPath)
		if err != nil {
			return nil, fmt.Errorf("local: read identities: %w", err)
		}
	}

	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("local: parse identities: %w", err)
	}
	for _, id := range ids {
		switch id.(type) {
		case *age.X25519Identity, *age.HybridIdentity:
		default:
			return nil, fmt.Errorf("local: unsupported identity type %T in %s", id, p.IdentityPath)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("local: %s contains no identities", p.IdentityPath)
	}
	return ids, nil
}

// migrateLegacyIdentity copies a pre-rename identity.txt sibling of
// p.IdentityPath (if one exists) into p.IdentityPath, so upgrading past
// the identity.txt -> identities rename doesn't orphan an existing
// private key. Returns false, nil if no legacy file exists.
func (p *Provider) migrateLegacyIdentity() (bool, error) {
	legacyPath := filepath.Join(filepath.Dir(p.IdentityPath), "identity.txt")
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("local: read legacy identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
		return false, fmt.Errorf("local: create identity dir: %w", err)
	}
	if err := os.WriteFile(p.IdentityPath, data, 0o600); err != nil {
		return false, fmt.Errorf("local: migrate legacy identity: %w", err)
	}
	return true, nil
}
