package provider

import (
	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newLocal keys off this machine's age identity.
func newLocal() (*vault.Vault, []string, error) {
	p, err := local.New()
	if err != nil {
		return nil, nil, err
	}
	recipient, err := p.Recipient()
	if err != nil {
		return nil, nil, err
	}
	return build(p, recipient)
}

// rotateLocal adds an identity and keeps the old ones, so one vault
// serves both roles: Decrypt matches whichever identity a file names,
// Encrypt targets the newest.
func rotateLocal(cfg config.Config) (Rotation, error) {
	p, err := local.New()
	if err != nil {
		return Rotation{}, err
	}
	if _, err := p.Rotate(); err != nil {
		return Rotation{}, err
	}

	rot, err := reseal(config.Config{Provider: local.Name})
	if err != nil {
		return Rotation{}, err
	}
	rot.Config = cfg
	return rot, nil
}
