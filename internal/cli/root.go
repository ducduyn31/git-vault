// Package cli defines git-vault's subcommands: flag parsing, prompting,
// and output. The work each command does lives elsewhere — see
// internal/provider (which key provider, and building its vault),
// internal/gitcmd (git plumbing), and internal/gitattr (.gitattributes).
package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitcmd"
)

var callerPrefix string

// NewRootCmd builds the git-vault root cobra command with all subcommands
// wired in.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "git-vault",
		Short:         "Transparently encrypt secret files in a git repository",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return chdirToToplevel()
		},
	}
	root.AddCommand(
		newLoginCmd(),
		newTrackCmd(),
		newInstallCmd(),
		newUninstallCmd(),
		newMigrateCmd(),
		newRotateCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newCleanCmd(),
		newSmudgeCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)
	return root
}

// chdirToToplevel moves the process to the working tree root, recording
// where the caller stood. Outside a working tree it does nothing, leaving
// each command to report its own missing-config or missing-file error.
func chdirToToplevel() error {
	callerPrefix = ""
	root, prefix, err := gitcmd.Toplevel()
	if err != nil {
		return nil
	}
	callerPrefix = prefix
	return os.Chdir(root)
}

// repoPath re-anchors a user-supplied path or pattern to the repo root,
// so `git vault encrypt secret.yaml` inside sub/ means sub/secret.yaml.
func repoPath(p string) string {
	if callerPrefix == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(callerPrefix, p)
}

// Execute runs the root command against the real process args.
func Execute() error {
	return NewRootCmd().Execute()
}
