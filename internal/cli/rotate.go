package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/ui"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newRotateCmd re-seals every tracked file under fresh key material for
// the repo's *current* provider — unlike migrate, the provider name never
// changes. For every provider except azurekms, .git-vault.yaml is never
// rewritten either; azurekms is the one exception, since its key URL is
// pinned to a specific Key Vault key version (see its case below). See
// docs/superpowers/specs/2026-07-11-provider-key-rotation-design.md and
// docs/superpowers/specs/2026-07-12-azurekms-provider-design.md.
func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new key and re-seal all tracked files under it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			oldVault, _, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			var newVault *vault.Vault
			var newRecipients []string
			switch cfg.Provider {
			case local.Name:
				provider, err := local.New()
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				if _, err := provider.Rotate(); err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				// One vault now serves both roles: Decrypt matches
				// whichever stored identity a file names, and the
				// freshly rotated identity is the newest, so Encrypt
				// targets it.
				newVault, newRecipients, err = vaultForProvider(config.Config{Provider: local.Name})
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
			case passphrase.Name:
				newSecret, err := passphrase.PromptNewSecret(cmd.OutOrStdout())
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				registry := keyservice.NewRegistry()
				if err := registry.Register(passphrase.NewWithSecret(newSecret)); err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				newVault = vault.New(keyservice.NewServer(registry))
				newRecipients = []string{passphrase.Name + ":" + passphrase.KeyID}
			case gcpkms.Name:
				// The resource ID never changes across a GCP-side rotation — only
				// which key version is primary does, invisible to git-vault.
				// Re-sealing every file forces a fresh KMS Encrypt call, which GCP
				// always services with the current primary version, moving every
				// file's wrapped data key off whatever version it was on before.
				newVault, newRecipients, err = vaultForProvider(cfg)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
			case azurekms.Name:
				// Azure Key Vault key URLs are version-pinned (unlike GCP's
				// resource ID), so if the key was rotated in Azure since
				// install or the last rotation, cfg.KeyResourceID may still
				// point at a stale version. Re-resolve to the vault's
				// current version first and persist it below, so re-sealing
				// actually moves every file onto that version instead of
				// re-encrypting under the old one.
				resolved, err := azurekms.New().CurrentVersionURL(cmd.Context(), cfg.KeyResourceID)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				cfg.KeyResourceID = resolved
				newVault, newRecipients, err = vaultForProvider(cfg)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
			default:
				return fmt.Errorf("git vault rotate: rotation not supported for provider %q", cfg.Provider)
			}

			n, err := resealTracked(oldVault, newVault, newRecipients)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			if cfg.Provider == azurekms.Name {
				if err := config.Save(config.DefaultFileName, cfg); err != nil {
					return fmt.Errorf("git vault rotate: write %s: %w", config.DefaultFileName, err)
				}
			}

			var followUp string
			switch cfg.Provider {
			case local.Name:
				followUp = "Old identity is retained to decrypt anything not yet migrated (including committed history)."
			case passphrase.Name:
				followUp = "Distribute the new passphrase to your team out-of-band, and keep GIT_VAULT_PASSPHRASE set to the old value followed by the new value (one per line) until everyone has migrated — then the old line can be dropped."
			case gcpkms.Name:
				followUp = "Old KMS key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable or destroy the old version(s) in GCP to complete the rotation."
			case azurekms.Name:
				followUp = "Old Key Vault key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable the old version in Azure to complete the rotation."
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf(
				"Rotated %d file(s) under %q.\n%s\nRun `git add -A && git commit` to finish — committed ciphertext still needs the old key until you do.",
				n, cfg.Provider, followUp,
			))
			return nil
		},
	}
}
