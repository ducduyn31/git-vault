package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/vault"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show git-vault-tracked files and their encryption state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			patterns, err := gitattr.Tracked(".gitattributes")
			if err != nil {
				return fmt.Errorf("git vault status: %w", err)
			}
			out := cmd.OutOrStdout()
			if len(patterns) == 0 {
				_, err := fmt.Fprintln(out, "No files tracked by git-vault. Run `git vault track <pattern>` to start.")
				return err
			}

			files, err := trackedFiles(patterns)
			if err != nil {
				return fmt.Errorf("git vault status: %w", err)
			}
			if len(files) == 0 {
				_, err := fmt.Fprintln(out, "No committed files match the tracked patterns yet.")
				return err
			}

			for _, f := range files {
				sealed, sealErr := vault.IsSealed(f)
				if sealErr != nil {
					if _, err := fmt.Fprintf(out, "%s\terror: %v\n", f, sealErr); err != nil {
						return err
					}
					continue
				}
				state := "plaintext"
				if sealed {
					state = "encrypted"
				}
				if _, err := fmt.Fprintf(out, "%s\t%s\n", f, state); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// trackedFiles resolves .gitattributes patterns to the working-tree paths
// git itself considers tracked, using git's own pathspec matching rather
// than reimplementing gitignore-style globbing.
func trackedFiles(patterns []string) ([]string, error) {
	args := append([]string{"ls-files", "--"}, patterns...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}
