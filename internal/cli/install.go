package cli

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/ui"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			global, err := cmd.Flags().GetBool("global")
			if err != nil {
				return err
			}
			providerName, err := cmd.Flags().GetString("provider")
			if err != nil {
				return err
			}
			keyResourceID, err := cmd.Flags().GetString("key-resource-id")
			if err != nil {
				return err
			}
			awsProfile, err := cmd.Flags().GetString("aws-profile")
			if err != nil {
				return err
			}
			autoLogin, err := cmd.Flags().GetBool("auto-login")
			if err != nil {
				return err
			}

			if (providerName == gcpkms.Name || providerName == awskms.Name || providerName == azurekms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", providerName)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID, AwsProfile: awsProfile, AutoLogin: autoLogin}

			// vaultForProvider validates the provider name and resolves
			// the recipient to print — same switch newVault uses.
			_, recipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

			switch providerName {
			case gcpkms.Name:
				err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, autoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			case awskms.Name:
				err := verifyAWSKMSRoundTrip(cmd.Context(), keyResourceID, awsProfile)
				if errors.Is(err, awskms.ErrExpiredSSOSession) && attemptAWSSSOLogin(cmd, awsProfile, autoLogin) {
					err = verifyAWSKMSRoundTrip(cmd.Context(), keyResourceID, awsProfile)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			case azurekms.Name:
				err := verifyAzureKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, azurekms.ErrNoCredentials) && attemptAzLogin(cmd, autoLogin) {
					err = verifyAzureKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}

			settings := []struct{ key, value string }{
				{"filter.git-vault.clean", "git-vault clean %f"},
				{"filter.git-vault.smudge", "git-vault smudge %f"},
				{"filter.git-vault.required", "true"},
			}
			for _, s := range settings {
				if err := setGitConfig(global, s.key, s.value); err != nil {
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
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms, awskms, azurekms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, or Azure Key Vault key URL (required when --provider gcpkms, awskms, or azurekms)")
	cmd.Flags().String("aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	cmd.Flags().Bool("auto-login", false, "skip the confirmation prompt and run the provider's login command automatically when credentials are missing (gcpkms, awskms, azurekms)")
	return cmd
}

func setGitConfig(global bool, key, value string) error {
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, key, value)

	out, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", key, err, out)
	}
	return nil
}
