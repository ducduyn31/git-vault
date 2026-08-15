package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/gitcmd"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/session"
	"github.com/ducduyn31/git-vault/internal/ui"
	"github.com/ducduyn31/git-vault/internal/vault"
)

func newUninstallCmd() *cobra.Command {
	var global, purgeConfig, purgeAttrs, purgeKeys, force bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Unregister the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sealed, plaintext, err := trackedFileStates()
			if err != nil {
				return fmt.Errorf("git vault uninstall: %w", err)
			}

			if purgeKeys {
				var sealedForPrompt []string
				if cfg, cfgErr := config.Load(config.DefaultFileName); cfgErr == nil && cfg.Provider == local.Name {
					sealedForPrompt = sealed
				}
				confirmed, err := confirmPurgeKeys(cmd.OutOrStdout(), cmd.InOrStdin(), force, sealedForPrompt)
				if err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
				if !confirmed {
					return fmt.Errorf("git vault uninstall: aborted, --purge-keys declined")
				}
			}

			for _, key := range []string{"filter.git-vault.clean", "filter.git-vault.smudge", "filter.git-vault.required"} {
				if err := gitcmd.UnsetConfig(global, key); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeKeys {
				if err := purgeLocalKeys(); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeAttrs {
				if err := gitattr.Untrack(".gitattributes"); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeConfig {
				if err := removeIfExists(config.DefaultFileName); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			scope := "repo"
			if global {
				scope = "global"
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Uninstalled git-vault filter driver (%s scope).", scope))

			if len(plaintext) > 0 {
				ui.Warn(cmd.OutOrStdout(), fmt.Sprintf(
					"%d file(s) tracked by git-vault are currently plaintext and no longer protected now that the filter driver is unregistered:\n  %s\nThey will be committed as plaintext if staged before you reinstall (`git vault install`) or handle them manually.",
					len(plaintext), strings.Join(plaintext, "\n  "),
				))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "unregister the filter driver from the user's global git config")
	cmd.Flags().BoolVar(&purgeConfig, "purge-config", false, "also remove "+config.DefaultFileName)
	cmd.Flags().BoolVar(&purgeAttrs, "purge-attrs", false, "also remove git-vault's filter lines from .gitattributes")
	cmd.Flags().BoolVar(&purgeKeys, "purge-keys", false, "also delete this machine's local key material and cached session (irreversible: encrypted files become permanently unreadable unless the key is backed up elsewhere)")
	cmd.Flags().BoolVar(&force, "force", false, "skip the --purge-keys confirmation prompt")
	return cmd
}

// confirmPurgeKeys prompts on out/in unless force is set, naming sealed
// (files currently encrypted under the local provider) when known, or a
// generic irreversibility warning otherwise. Returns whether to proceed.
func confirmPurgeKeys(out io.Writer, in io.Reader, force bool, sealed []string) (bool, error) {
	if force {
		return true, nil
	}

	if len(sealed) > 0 {
		if _, err := fmt.Fprintf(out, "The following %d file(s) appear to be encrypted with the local key about to be deleted:\n", len(sealed)); err != nil {
			return false, err
		}
		for _, f := range sealed {
			if _, err := fmt.Fprintf(out, "  %s\n", f); err != nil {
				return false, err
			}
		}
		if _, err := fmt.Fprintln(out, "They will become permanently unreadable unless you have a backup of the key."); err != nil {
			return false, err
		}
	} else {
		if _, err := fmt.Fprintln(out, "This deletes git-vault's local key material and cached session for this machine."); err != nil {
			return false, err
		}
	}
	if _, err := fmt.Fprint(out, "This is irreversible. Continue? [y/N] "); err != nil {
		return false, err
	}

	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// trackedFileStates enumerates git-vault-tracked files the same way
// status.go does, splitting them into currently-sealed (ciphertext) and
// currently-plaintext. Both empty if nothing is tracked. A file that
// fails vault.IsSealed (e.g. unreadable) is skipped rather than failing
// the whole scan — this feeds a best-effort warning, not a correctness
// check.
func trackedFileStates() (sealed, plaintext []string, err error) {
	patterns, err := gitattr.Tracked(".gitattributes")
	if err != nil {
		return nil, nil, err
	}
	if len(patterns) == 0 {
		return nil, nil, nil
	}

	files, err := gitcmd.TrackedFiles(patterns)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		ok, sealErr := vault.IsSealed(f)
		if sealErr != nil {
			continue
		}
		if ok {
			sealed = append(sealed, f)
		} else {
			plaintext = append(plaintext, f)
		}
	}
	return sealed, plaintext, nil
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
