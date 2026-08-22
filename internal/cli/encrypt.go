package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/provider"

	"github.com/ducduyn31/git-vault/internal/ui"
)

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, recipients, err := provider.Current()
			if err != nil {
				return err
			}
			path := repoPath(args[0])
			if err := v.Seal(path, recipients); err != nil {
				return err
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Sealed %s", path))
			return nil
		},
	}
}
