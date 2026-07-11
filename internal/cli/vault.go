package cli

import (
	"fmt"
	"os"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newLocalVault builds a Vault dispatching to this machine's local age
// identity, along with the "<provider>:<key-id>" recipient string that
// identity resolves to.
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

// newPassphraseVault builds a Vault dispatching to the shared secret in
// passphrase.EnvVar, along with its fixed "<provider>:<key-id>" recipient
// string.
func newPassphraseVault() (*vault.Vault, []string, error) {
	provider := passphrase.New()

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{passphrase.Name + ":" + passphrase.KeyID}, nil
}

// vaultForProvider builds the Vault for the named provider.
func vaultForProvider(name string) (*vault.Vault, []string, error) {
	switch name {
	case local.Name:
		return newLocalVault()
	case passphrase.Name:
		return newPassphraseVault()
	default:
		return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", name, config.DefaultFileName)
	}
}

// loadConfig reads .git-vault.yaml, wrapping a missing file with a hint
// to run `git vault install` instead of surfacing a raw os.PathError.
func loadConfig() (config.Config, error) {
	cfg, err := config.Load(config.DefaultFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return config.Config{}, fmt.Errorf("git vault: no %s found, run \"git vault install\" first", config.DefaultFileName)
		}
		return config.Config{}, fmt.Errorf("git vault: read %s: %w", config.DefaultFileName, err)
	}
	return cfg, nil
}

// newVault loads .git-vault.yaml and builds the Vault for whichever
// provider it names. Every command that seals or opens a file (encrypt,
// decrypt, clean, smudge) shares this instead of repeating the
// config/registry/server wiring.
func newVault() (*vault.Vault, []string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	return vaultForProvider(cfg.Provider)
}
