package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/ui"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newRotateCmd re-seals every tracked file under fresh key material for
// the repo's *current* provider — unlike migrate, the provider name never
// changes, so .git-vault.yaml is never rewritten. See
// docs/superpowers/specs/2026-07-11-provider-key-rotation-design.md.
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
			case awskms.Name:
				// The ARN never changes across an AWS-side rotation, and
				// AWS KMS's automatic annual rotation is fully transparent
				// — there is no "current version" exposed to target the
				// way GCP's key versions are. Re-sealing every file still
				// forces a fresh KMS Encrypt call; it just doesn't let old
				// backing material be individually retired afterward the
				// way gcpkms's case does.
				newVault, newRecipients, err = vaultForProvider(cfg)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
			default:
				return fmt.Errorf("git vault rotate: rotation not supported for provider %q", cfg.Provider)
			}

			patterns, err := gitattr.Tracked(".gitattributes")
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}
			var files []string
			if len(patterns) > 0 {
				files, err = trackedFiles(patterns)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
			}

			for _, f := range files {
				if err := oldVault.Open(f); err != nil {
					return fmt.Errorf("git vault rotate: decrypt %s: %w", f, err)
				}
				if err := newVault.Seal(f, newRecipients); err != nil {
					return fmt.Errorf("git vault rotate: re-seal %s: %w", f, err)
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
			case awskms.Name:
				followUp = "AWS KMS rotates its backing key material automatically and transparently — unlike GCP, there is no old version to disable or destroy afterward; this re-encryption is defense-in-depth only. To actually retire a compromised key, use `git vault migrate` to a different KMS key instead."
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf(
				"Rotated %d file(s) under %q.\n%s\nRun `git add -A && git commit` to finish — committed ciphertext still needs the old key until you do.",
				len(files), cfg.Provider, followUp))
			return nil
		},
	}
}
