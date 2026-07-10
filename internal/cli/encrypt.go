package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault encrypt: not implemented in scaffold")
		},
	}
}
