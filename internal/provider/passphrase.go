package provider

import (
	"io"

	"github.com/ducduyn31/git-vault/internal/config"

	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newPassphrase keys off the shared secret in passphrase.EnvVar.
func newPassphrase() (*vault.Vault, []string, error) {
	p := passphrase.New()
	if err := p.Ready(); err != nil {
		return nil, nil, err
	}
	return build(p, passphrase.KeyID)
}

// rotatePassphrase seals under a new secret while old keeps decrypting
// the previous one — the team needs both until everyone has migrated.
func rotatePassphrase(out io.Writer, old *vault.Vault, cfg config.Config) (Rotation, error) {
	secret, err := passphrase.PromptNewSecret(out)
	if err != nil {
		return Rotation{}, err
	}

	v, recipients, err := build(passphrase.NewWithSecret(secret), passphrase.KeyID)
	if err != nil {
		return Rotation{}, err
	}
	return Rotation{Old: old, New: v, Recipients: recipients, Config: cfg}, nil
}
