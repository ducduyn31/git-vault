package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault install: not implemented in scaffold")
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	return cmd
}
