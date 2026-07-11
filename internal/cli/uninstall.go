package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/session"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Unregister the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			global, err := cmd.Flags().GetBool("global")
			if err != nil {
				return err
			}
			purgeConfig, err := cmd.Flags().GetBool("purge-config")
			if err != nil {
				return err
			}
			purgeKeys, err := cmd.Flags().GetBool("purge-keys")
			if err != nil {
				return err
			}

			for _, key := range []string{"filter.git-vault.clean", "filter.git-vault.smudge", "filter.git-vault.required"} {
				if err := unsetGitConfig(global, key); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeConfig {
				if err := removeIfExists(config.DefaultFileName); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeKeys {
				if err := purgeLocalKeys(); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			scope := "repo"
			if global {
				scope = "global"
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Uninstalled git-vault filter driver (%s scope).\n", scope); err != nil {
				return fmt.Errorf("git vault uninstall: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "unregister the filter driver from the user's global git config")
	cmd.Flags().Bool("purge-config", false, "also remove "+config.DefaultFileName)
	cmd.Flags().Bool("purge-keys", false, "also delete this machine's local key material and cached session (irreversible: encrypted files become permanently unreadable unless the key is backed up elsewhere)")
	return cmd
}

// unsetGitConfig removes key from git config, treating "key not set" (git's
// exit code 5) as success so uninstall stays idempotent.
func unsetGitConfig(global bool, key string) error {
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, "--unset", key)

	out, err := exec.Command("git", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
		return nil
	}
	return fmt.Errorf("git %s: %w: %s", key, err, out)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// purgeLocalKeys deletes this machine's local-provider identities (see
// internal/keyservice/local) and cached session, honoring
// local.IdentityPathEnvVar the same way the provider itself does.
func purgeLocalKeys() error {
	provider, err := local.New()
	if err != nil {
		return err
	}
	if err := removeIfExists(provider.IdentityPath); err != nil {
		return err
	}

	sessionPath, err := session.DefaultPath()
	if err != nil {
		return err
	}
	return removeIfExists(sessionPath)
}
