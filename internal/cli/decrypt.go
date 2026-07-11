package cli

import "github.com/spf13/cobra"

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := newVault()
			if err != nil {
				return err
			}
			return v.Open(args[0])
		},
	}
}
