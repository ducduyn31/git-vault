package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
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

			if providerName == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", gcpkms.Name)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID}

			// vaultForProvider both validates providerName (its default
			// case errors on anything unknown) and resolves the
			// "<provider>:<key-id>" recipient to print, via the same
			// switch newVault() uses at encrypt/decrypt/clean/smudge time
			// — no separate recipient-resolution switch needed here.
			_, recipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

			if providerName == gcpkms.Name {
				if err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID); err != nil {
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
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed git-vault filter driver (%s scope).\nRecipient: %s\n", scope, recipient); err != nil {
				return fmt.Errorf("git vault install: print recipient: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID (required when --provider gcpkms)")
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
