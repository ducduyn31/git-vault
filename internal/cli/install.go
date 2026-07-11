package cli

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
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
			autoLogin, err := cmd.Flags().GetBool("auto-login")
			if err != nil {
				return err
			}

			if providerName == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", gcpkms.Name)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID, AutoLogin: autoLogin}

			// vaultForProvider validates the provider name and resolves
			// the recipient to print — same switch newVault uses.
			_, recipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

			if providerName == gcpkms.Name {
				err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, autoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
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
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID (required when --provider gcpkms)")
	cmd.Flags().Bool("auto-login", false, "skip the confirmation prompt and run gcloud auth application-default login automatically when ADC is missing (gcpkms only)")
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
