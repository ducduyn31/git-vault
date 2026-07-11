package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/ui"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms it's only
// true when the resource ID also matches, since two different gcpkms
// targets can share the provider name but name different keys. See
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md and
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md.
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
			keyResourceID, err := cmd.Flags().GetString("key-resource-id")
			if err != nil {
				return err
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			if target == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", gcpkms.Name)
			}

			targetCfg := config.Config{Provider: target, KeyResourceID: keyResourceID}

			oldVault, oldRecipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			newVault, newRecipients, err := vaultForProvider(targetCfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			if len(oldRecipients) == 1 && len(newRecipients) == 1 && oldRecipients[0] == newRecipients[0] {
				return fmt.Errorf("git vault migrate: target is identical to the current key (%s); nothing to migrate", oldRecipients[0])
			}

			n, err := resealTracked(oldVault, newVault, newRecipients)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			if err := config.Save(config.DefaultFileName, targetCfg); err != nil {
				return fmt.Errorf("git vault migrate: write %s: %w", config.DefaultFileName, err)
			}

			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf(
				"Migrated %d file(s) from %q to %q.\nWorking tree is now sealed under %q; run `git add -A && git commit` to finish — committed ciphertext still needs %q until you do.",
				n, cfg.Provider, target, target, cfg.Provider,
			))
			return nil
		},
	}
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID (required when --provider gcpkms)")
	return cmd
}
