package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

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

			provider, err := local.New()
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient, err := provider.Recipient()
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
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

			scope := "repo"
			if global {
				scope = "global"
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed git-vault filter driver (%s scope).\nRecipient: %s:%s\n", scope, local.Name, recipient); err != nil {
				return fmt.Errorf("git vault install: print recipient: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
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
