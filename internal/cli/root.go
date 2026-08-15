// Package cli defines git-vault's subcommands: flag parsing, prompting,
// and output. The work each command does lives elsewhere — see
// internal/provider (which key provider, and building its vault),
// internal/gitcmd (git plumbing), and internal/gitattr (.gitattributes).
package cli

import "github.com/spf13/cobra"

// NewRootCmd builds the git-vault root cobra command with all subcommands
// wired in.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "git-vault",
		Short:         "Transparently encrypt secret files in a git repository",
		SilenceErrors: true,
		SilenceUsage:  true,
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

// Execute runs the root command against the real process args.
func Execute() error {
	return NewRootCmd().Execute()
}
