package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/ui"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms/awskms/azurekms
// it's only true when the resource ID/ARN/URL also matches, since two
// different targets can share the provider name but name different keys.
// See docs/superpowers/specs/2026-07-11-migrate-provider-design.md,
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md,
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md, and
// docs/superpowers/specs/2026-07-12-azurekms-provider-design.md.
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
			awsProfile, err := cmd.Flags().GetString("aws-profile")
			if err != nil {
				return err
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			if (target == gcpkms.Name || target == awskms.Name || target == azurekms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", target)
			}

			targetCfg := config.Config{Provider: target, KeyResourceID: keyResourceID, AwsProfile: awsProfile}

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

			// Fail fast on a bad target key before resealTracked decrypts
			// anything to plaintext on disk: resealTracked opens each
			// tracked file under the OLD key before sealing it under the
			// new one, so a malformed/unreachable target key would
			// otherwise be discovered only after the first file is already
			// plaintext, with .git-vault.yaml never updated. Mirrors the
			// same round-trip check install.go runs before touching git
			// config — see verifyGCPKMSRoundTrip/verifyAWSKMSRoundTrip/
			// verifyAzureKMSRoundTrip in login.go. Unlike install/login,
			// migrate does not offer to run gcloud/aws sso/az login on
			// failure: it's a rarer, more deliberate operation than initial
			// setup.
			switch target {
			case gcpkms.Name:
				if err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID); err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
			case awskms.Name:
				if err := verifyAWSKMSRoundTrip(cmd.Context(), keyResourceID, awsProfile); err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
			case azurekms.Name:
				if err := verifyAzureKMSRoundTrip(cmd.Context(), keyResourceID); err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
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
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms, awskms, azurekms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, or Azure Key Vault key URL (required when --provider gcpkms, awskms, or azurekms)")
	cmd.Flags().String("aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	return cmd
}
