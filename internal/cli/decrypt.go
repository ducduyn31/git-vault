package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/provider"

	"github.com/ducduyn31/git-vault/internal/ui"
)

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := provider.Current()
			if err != nil {
				return err
			}
			path := repoPath(args[0])
			if err := v.Open(path); err != nil {
				return err
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Opened %s", path))
			return nil
		},
	}
}
