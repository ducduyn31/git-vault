package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/provider"

	"github.com/ducduyn31/git-vault/internal/vault"
)

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clean <path>",
		Short:  "Git clean filter entry point (encrypt on stage)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, recipients, err := provider.Current()
			if err != nil {
				return err
			}
			return v.SealStream(cmd.OutOrStdout(), cmd.InOrStdin(), vault.FormatForPath(args[0]), recipients)
		},
	}
}
