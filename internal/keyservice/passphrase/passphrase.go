// Package passphrase implements a keyservice.Provider backed by a shared
// secret read from an environment variable, encrypted with age's scrypt
// (password-based) recipient. Unlike internal/keyservice/local, the same
// passphrase can be distributed to a team out-of-band (e.g. a secrets
// manager or password vault) — there is no per-machine identity and no
// login flow, at the cost of weaker rotation and audit than a real
// SSO/KMS-backed provider.
package passphrase

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Name is the provider name used in "passphrase:<key-id>" key identifiers
// (see internal/keyservice.Server).
const Name = "passphrase"

// EnvVar is the environment variable this provider reads its shared
// secret from.
const EnvVar = "GIT_VAULT_PASSPHRASE"

// KeyID is the fixed key-id this provider uses: the passphrase is a
// single shared secret, not a per-recipient key, so there is nothing to
// distinguish one key-id from another.
const KeyID = "shared"

// Provider is a Provider backed by the passphrase in EnvVar. It holds no
// state; the passphrase is read fresh on every Encrypt/Decrypt call.
type Provider struct{}

// New returns a Provider.
func New() Provider { return Provider{} }

func (Provider) Name() string { return Name }

// Encrypt encrypts plaintext (a sops data key) using real age scrypt
// encryption, armored (see armor.NewWriter below) so the result is safe
// to store as a string inside a YAML/JSON document — raw binary age
// output is not valid UTF-8 and JSON in particular would silently
// corrupt it. keyID is ignored: the passphrase is the only key material.
func (Provider) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	secret, err := lookupPassphrase()
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(secret)
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored ciphertext (see Encrypt) using the passphrase
// in EnvVar. keyID is ignored, for the same reason as Encrypt.
func (Provider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	secret, err := lookupPassphrase()
	if err != nil {
		return nil, err
	}
	identity, err := age.NewScryptIdentity(secret)
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, identity)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	return plaintext, nil
}

func lookupPassphrase() (string, error) {
	secret := os.Getenv(EnvVar)
	if secret == "" {
		return "", fmt.Errorf("passphrase: %s not set", EnvVar)
	}
	return secret, nil
}
