package cli

import "github.com/spf13/cobra"

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, recipients, err := newVault()
			if err != nil {
				return err
			}
			return v.Seal(args[0], recipients)
		},
	}
}
