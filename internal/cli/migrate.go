package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/provider"
	"github.com/ducduyn31/git-vault/internal/ui"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms/awskms/azurekms/hclvault
// it's only true when the resource ID/ARN/URL also matches, since two
// different targets can share the provider name but name different keys.
func newMigrateCmd() *cobra.Command {
	var target, keyResourceID, awsProfile string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Re-seal all tracked files under a different key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("git vault migrate: --provider is required")
			}

			cfg, err := provider.LoadConfig()
			if err != nil {
				return err
			}

			if _, remote := provider.Remotes[target]; remote && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", target)
			}

			targetCfg := config.Config{Provider: target, KeyResourceID: keyResourceID, AwsProfile: awsProfile}

			oldVault, oldRecipients, err := provider.ForConfig(cfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			newVault, newRecipients, err := provider.ForConfig(targetCfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			if len(oldRecipients) == 1 && len(newRecipients) == 1 && oldRecipients[0] == newRecipients[0] {
				return fmt.Errorf("git vault migrate: target is identical to the current key (%s); nothing to migrate", oldRecipients[0])
			}

			// Fail fast on a bad target key: ResealTracked opens each file
			// under the old key before sealing it under the new one, so a
			// bad target would otherwise surface mid-reseal, with files
			// already plaintext and .git-vault.yaml never updated. No
			// auto-login — migrate is deliberate enough to not offer one.
			if err := verifyRoundTrip(cmd, targetCfg, false); err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			n, err := provider.ResealTracked(oldVault, newVault, newRecipients)
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
	cmd.Flags().StringVar(&target, "provider", "", "target key provider to migrate to (local, passphrase, gcpkms, awskms, azurekms, vault)")
	cmd.Flags().StringVar(&keyResourceID, "key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, Azure Key Vault key URL, or Vault Transit key URL (required when --provider gcpkms, awskms, azurekms, or vault)")
	cmd.Flags().StringVar(&awsProfile, "aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	return cmd
}
