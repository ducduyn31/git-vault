// Package hcvault implements a keyservice.Provider backed by HashiCorp
// Vault's Transit secrets engine, authorized via whatever bearer token
// sops's own hcvault package resolves on this machine (the VAULT_TOKEN
// env var, then ~/.vault-token — the file the `vault` CLI's `vault login`
// writes). Unlike internal/keyservice/local and .../passphrase, git-vault
// holds no key material of its own here: Vault's ACL policy on the
// Transit key is the only access control, and git-vault never implements
// its own auth flow — `git vault login` (internal/cli/login.go) only ever
// shells out to the real `vault login`, and only with the user's explicit
// confirmation (or config.Config.AutoLogin). See
// docs/superpowers/specs/2026-07-14-vault-provider-design.md.
package hcvault

import (
	"context"
	"errors"
	"fmt"
	"os"

	sopshcvault "github.com/getsops/sops/v3/hcvault"
	vaultapi "github.com/hashicorp/vault/api"
)

// Name is the provider name used in "vault:<key-url>" key identifiers
// (see internal/keyservice.Server).
const Name = "vault"

// testToken overrides the token every MasterKey this package's Providers
// create authenticates with. Set only via SetTestOverridesForTesting.
var testToken string

// SetTestOverridesForTesting points every Provider subsequently created
// by New at a fixed token instead of the real VAULT_TOKEN/~/.vault-token
// resolution, so tests can run against a fake server (see hcvaulttest)
// without real Vault credentials. It returns a function that restores the
// previous override — call it via defer. For use in tests only.
func SetTestOverridesForTesting(token string) (restore func()) {
	prev := testToken
	testToken = token
	return func() { testToken = prev }
}

// Provider is backed by a Vault Transit key, identified per-call by keyID
// (a full Transit key URL) rather than fixed at construction — the URL
// lives in git-vault's repo-tracked config
// (internal/config.Config.KeyResourceID), not in this Provider.
type Provider struct {
	token string
}

// New returns a Provider using real Vault token resolution, unless
// SetTestOverridesForTesting has redirected it to a fixed test token.
func New() Provider {
	return Provider{token: testToken}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the Vault Transit key
// named by keyID (a URL of the form
// https://<vault-addr>/v1/<enginePath>/keys/<keyName>).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key, err := p.parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the Vault Transit key
// named by keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key, err := p.parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// parseKeyID builds a sops hcvault.MasterKey from keyID, applies this
// Provider's test token override (if any), and pins
// SOPS_HC_VAULT_ALLOWLIST to the key's parsed VaultAddress so sops's
// client only ever talks to the configured Vault, not whatever the
// ambient environment might otherwise allow (its default is "allow every
// host").
func (p Provider) parseKeyID(keyID string) (*sopshcvault.MasterKey, error) {
	if keyID == "" {
		return nil, errors.New("hcvault: key ID is required (a Vault Transit key URL)")
	}
	key, err := sopshcvault.NewMasterKeyFromURI(keyID)
	if err != nil {
		return nil, fmt.Errorf("hcvault: %w", err)
	}
	_ = os.Setenv(sopshcvault.SopsHCVaultAllowlist, key.VaultAddress)
	if p.token != "" {
		sopshcvault.Token(p.token).ApplyToMasterKey(key)
	}
	return key, nil
}

// ErrNoValidToken is returned (via friendlyLoginErr) when Vault responds
// with 403 permission denied — Vault's single status for a missing,
// invalid, or expired token, or a valid token lacking the right ACL
// policy. It's a sentinel rather than just a message so callers — namely
// internal/cli/login.go — can detect this specific, fixable case with
// errors.Is and offer to run `vault login` themselves, instead of every
// caller re-parsing error text.
var ErrNoValidToken = errors.New("hcvault: no valid Vault token — run `vault login` first")

// friendlyLoginErr rewrites a Vault 403 response into ErrNoValidToken.
// Any other error (network failure, sealed vault, malformed key path) is
// wrapped with op but otherwise passed through as-is.
func friendlyLoginErr(op string, err error) error {
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 403 {
		return ErrNoValidToken
	}
	return fmt.Errorf("hcvault: %s: %w", op, err)
}
