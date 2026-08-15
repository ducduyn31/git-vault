// Package provider turns the provider named in .git-vault.yaml into a
// ready-to-use vault.Vault, and rotates or re-seals the files it sealed.
// Each provider's specifics live in its own file.
package provider

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/gitcmd"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// Remote is a provider whose key lives in an external KMS. Providers
// that keep their key locally have no Remote — nothing to authorize, and
// no key resource ID to name.
type Remote struct {
	Display   string
	LoginErr  error
	LoginHint string
	LoginArgv func(cfg config.Config) []string

	new func(cfg config.Config) keyservice.Provider
}

// Remotes is keyed by the provider name .git-vault.yaml uses.
var Remotes = map[string]Remote{
	gcpkms.Name:   gcpKMSRemote,
	awskms.Name:   awsKMSRemote,
	azurekms.Name: azureKMSRemote,
	hcvault.Name:  hcVaultRemote,
}

// Probe proves this machine can use the key cfg names by encrypting and
// decrypting against it, so callers can fail before touching git config
// or writing plaintext. A local-key provider has nothing to prove: nil.
func Probe(ctx context.Context, cfg config.Config) error {
	r, ok := Remotes[cfg.Provider]
	if !ok {
		return nil
	}
	return keyservice.ProbeRoundTrip(ctx, r.new(cfg), cfg.KeyResourceID)
}

// Rotation carries what re-sealing needs: Old decrypts what the previous
// key sealed, New encrypts, and Config differs from the caller's only
// when rotation changed it.
type Rotation struct {
	Old, New   *vault.Vault
	Recipients []string
	Config     config.Config
}

// Rotate produces fresh key material for cfg's provider, prompting on
// out when the new key comes from the user.
func Rotate(ctx context.Context, out io.Writer, cfg config.Config) (Rotation, error) {
	old, _, err := ForConfig(cfg)
	if err != nil {
		return Rotation{}, err
	}

	switch cfg.Provider {
	case local.Name:
		return rotateLocal(cfg)
	case passphrase.Name:
		return rotatePassphrase(out, old, cfg)
	case azurekms.Name:
		return rotateAzureKMS(ctx, cfg)
	case gcpkms.Name, awskms.Name, hcvault.Name:
		// These key IDs don't encode a version, so there's nothing to
		// re-resolve: re-sealing forces a fresh Encrypt, which each KMS
		// services with the key's current version.
		return reseal(cfg)
	default:
		return Rotation{}, fmt.Errorf("rotation not supported for provider %q", cfg.Provider)
	}
}

// reseal uses one vault for both roles — it still decrypts what the old
// key sealed.
func reseal(cfg config.Config) (Rotation, error) {
	v, recipients, err := ForConfig(cfg)
	if err != nil {
		return Rotation{}, err
	}
	return Rotation{Old: v, New: v, Recipients: recipients, Config: cfg}, nil
}

// build wires a Provider into the registry/server plumbing sops expects,
// returning its Vault and "<provider>:<key-id>" recipient.
func build(p keyservice.Provider, keyID string) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(p); err != nil {
		return nil, nil, err
	}
	return vault.New(keyservice.NewServer(registry)), []string{p.Name() + ":" + keyID}, nil
}

// ForConfig builds the Vault for the provider named in cfg. It takes the
// whole config because the remote-KMS providers need KeyResourceID.
func ForConfig(cfg config.Config) (*vault.Vault, []string, error) {
	switch cfg.Provider {
	case local.Name:
		return newLocal()
	case passphrase.Name:
		return newPassphrase()
	case gcpkms.Name:
		return newGCPKMS(cfg)
	case awskms.Name:
		return newAWSKMS(cfg)
	case azurekms.Name:
		return newAzureKMS(cfg)
	case hcvault.Name:
		return newHCVault(cfg)
	default:
		return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", cfg.Provider, config.DefaultFileName)
	}
}

// LoadConfig reads .git-vault.yaml, wrapping a missing file with a hint
// to run `git vault install` instead of surfacing a raw os.PathError.
func LoadConfig() (config.Config, error) {
	cfg, err := config.Load(config.DefaultFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return config.Config{}, fmt.Errorf("git vault: no %s found, run \"git vault install\" first", config.DefaultFileName)
		}
		return config.Config{}, fmt.Errorf("git vault: read %s: %w", config.DefaultFileName, err)
	}
	return cfg, nil
}

// ResealTracked decrypts every tracked file through from and re-seals it
// through to under recipients, returning how many. Nothing tracked is not
// an error.
func ResealTracked(from, to *vault.Vault, recipients []string) (int, error) {
	patterns, err := gitattr.Tracked(".gitattributes")
	if err != nil {
		return 0, err
	}
	if len(patterns) == 0 {
		return 0, nil
	}
	files, err := gitcmd.TrackedFiles(patterns)
	if err != nil {
		return 0, err
	}
	for _, f := range files {
		if err := from.Open(f); err != nil {
			return 0, fmt.Errorf("decrypt %s: %w", f, err)
		}
		if err := to.Seal(f, recipients); err != nil {
			return 0, fmt.Errorf("re-seal %s: %w", f, err)
		}
	}
	return len(files), nil
}

// Current builds the Vault for whichever provider .git-vault.yaml names.
func Current() (*vault.Vault, []string, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, nil, err
	}
	return ForConfig(cfg)
}
