package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/vault"
)

func newSmudgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "smudge <path>",
		Short:  "Git smudge filter entry point (decrypt on checkout)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := newVault()
			if err != nil {
				return err
			}
			return v.OpenStream(cmd.OutOrStdout(), cmd.InOrStdin(), vault.FormatForPath(args[0]))
		},
	}
}
