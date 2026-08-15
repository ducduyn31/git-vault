package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitcmd"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/provider"
	"github.com/ducduyn31/git-vault/internal/ui"
)

func newInstallCmd() *cobra.Command {
	var (
		global        bool
		providerName  string
		keyResourceID string
		awsProfile    string
		autoLogin     bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, remote := provider.Remotes[providerName]; remote && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", providerName)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID, AwsProfile: awsProfile, AutoLogin: autoLogin}

			_, recipients, err := provider.ForConfig(cfg)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

			if err := verifyRoundTrip(cmd, cfg, true); err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}

			settings := []struct{ key, value string }{
				{"filter.git-vault.clean", "git-vault clean %f"},
				{"filter.git-vault.smudge", "git-vault smudge %f"},
				{"filter.git-vault.required", "true"},
			}
			for _, s := range settings {
				if err := gitcmd.SetConfig(global, s.key, s.value); err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}

			if err := config.Save(config.DefaultFileName, cfg); err != nil {
				return fmt.Errorf("git vault install: write %s: %w", config.DefaultFileName, err)
			}

			scope := "repo"
			if global {
				scope = "global"
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Installed git-vault filter driver (%s scope).\nRecipient: %s", scope, recipient))
			return nil
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "install the filter driver in the user's global git config")
	cmd.Flags().StringVar(&providerName, "provider", local.Name, "key provider to use (local, passphrase, gcpkms, awskms, azurekms, vault)")
	cmd.Flags().StringVar(&keyResourceID, "key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, Azure Key Vault key URL, or Vault Transit key URL (required when --provider gcpkms, awskms, azurekms, or vault)")
	cmd.Flags().StringVar(&awsProfile, "aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	cmd.Flags().BoolVar(&autoLogin, "auto-login", false, "skip the confirmation prompt and run the provider's login command automatically when credentials are missing (gcpkms, awskms, azurekms, vault)")
	return cmd
}
