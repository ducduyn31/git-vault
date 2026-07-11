package cli

import (
	"fmt"
	"os"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
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
	if err := provider.Ready(); err != nil {
		return nil, nil, err
	}

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{passphrase.Name + ":" + passphrase.KeyID}, nil
}

// newGCPKMSVault builds a Vault dispatching to GCP KMS, along with the
// "<provider>:<key-id>" recipient string for cfg.KeyResourceID. Unlike
// local/passphrase, the key material lives entirely in GCP — this
// Provider holds no identity of its own beyond whatever ADC resolves to.
func newGCPKMSVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(gcpkms.New()); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{gcpkms.Name + ":" + cfg.KeyResourceID}, nil
}

// newAWSKMSVault builds a Vault dispatching to AWS KMS, along with the
// "<provider>:<key-id>" recipient string for cfg.KeyResourceID (an AWS
// KMS ARN). Unlike local/passphrase, the key material lives entirely in
// AWS — this Provider holds no identity of its own beyond whatever the
// default AWS credential chain (or cfg.AwsProfile) resolves to.
func newAWSKMSVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(awskms.New(cfg.AwsProfile)); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{awskms.Name + ":" + cfg.KeyResourceID}, nil
}

// vaultForProvider builds the Vault for the provider named in cfg. It
// takes the full config, not just the provider name, because gcpkms
// needs KeyResourceID — local/passphrase ignore everything but
// cfg.Provider.
func vaultForProvider(cfg config.Config) (*vault.Vault, []string, error) {
	switch cfg.Provider {
	case local.Name:
		return newLocalVault()
	case passphrase.Name:
		return newPassphraseVault()
	case gcpkms.Name:
		return newGCPKMSVault(cfg)
	case awskms.Name:
		return newAWSKMSVault(cfg)
	default:
		return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", cfg.Provider, config.DefaultFileName)
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
	return vaultForProvider(cfg)
}
