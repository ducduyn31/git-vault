package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
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

			if providerName == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault install: %s not set", passphrase.EnvVar)
			}

			// vaultForProvider both validates providerName (its default
			// case errors on anything unknown) and resolves the
			// "<provider>:<key-id>" recipient to print, via the same
			// switch newVault() uses at encrypt/decrypt/clean/smudge time
			// — no separate recipient-resolution switch needed here.
			_, recipients, err := vaultForProvider(providerName)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

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

			if err := config.Save(config.DefaultFileName, config.Config{Provider: providerName}); err != nil {
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
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase)")
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
