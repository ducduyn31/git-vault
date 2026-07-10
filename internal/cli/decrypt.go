package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault decrypt: not implemented in scaffold")
		},
	}
}
