package cli

import (
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newLocalVault builds a Vault dispatching to this machine's local age
// identity, along with the "<provider>:<key-id>" recipient string that
// identity resolves to. Every command that seals or opens a file
// (encrypt, decrypt, clean, smudge) shares this instead of repeating the
// provider/registry/server wiring.
func newLocalVault() (*vault.Vault, []string, error) {
	provider, err := local.New()
	if err != nil {
		return nil, nil, err
	}

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	recipient, err := provider.Recipient()
	if err != nil {
		return nil, nil, err
	}

	return vault.New(server), []string{local.Name + ":" + recipient}, nil
}
