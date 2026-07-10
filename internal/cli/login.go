package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with a git-vault key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault login: not implemented in scaffold")
		},
	}
}
