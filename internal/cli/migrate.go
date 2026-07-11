package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider to a different target provider, then updates .git-vault.yaml.
// Same-provider "rotation" is rejected rather than silently no-op'd: both
// existing providers (local, passphrase) have exactly one key source, so
// there is no old/new key pair to rotate between within one provider — see
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md.
func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Re-seal all tracked files under a different key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := cmd.Flags().GetString("provider")
			if err != nil {
				return err
			}
			if target == "" {
				return fmt.Errorf("git vault migrate: --provider is required")
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if target == cfg.Provider {
				return fmt.Errorf("git vault migrate: already using provider %q; in-place key rotation isn't supported (each provider has a single key source) — pick a different --provider", target)
			}

			if target == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault migrate: %s not set", passphrase.EnvVar)
			}

			oldVault, _, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			newVault, newRecipients, err := vaultForProvider(config.Config{Provider: target})
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			patterns, err := gitattr.Tracked(".gitattributes")
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			var files []string
			if len(patterns) > 0 {
				files, err = trackedFiles(patterns)
				if err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
			}

			for _, f := range files {
				if err := oldVault.Open(f); err != nil {
					return fmt.Errorf("git vault migrate: decrypt %s under %q: %w", f, cfg.Provider, err)
				}
				if err := newVault.Seal(f, newRecipients); err != nil {
					return fmt.Errorf("git vault migrate: re-seal %s under %q: %w", f, target, err)
				}
			}

			if err := config.Save(config.DefaultFileName, config.Config{Provider: target}); err != nil {
				return fmt.Errorf("git vault migrate: write %s: %w", config.DefaultFileName, err)
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"Migrated %d file(s) from %q to %q.\nWorking tree is now sealed under %q; run `git add -A && git commit` to finish — committed ciphertext still needs %q until you do.\n",
				len(files), cfg.Provider, target, target, cfg.Provider)
			if err != nil {
				return fmt.Errorf("git vault migrate: print summary: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase)")
	return cmd
}
