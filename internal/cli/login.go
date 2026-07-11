package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
)

// gcpkmsLoginProbe is the fixed plaintext used to verify a GCP KMS round
// trip. It carries no meaning beyond needing to survive
// Encrypt-then-Decrypt unchanged.
const gcpkmsLoginProbe = "git-vault-login-check"

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Verify this machine is authorized to use the repo's key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			if cfg.Provider != gcpkms.Name {
				return fmt.Errorf("git vault login: provider %q does not use git vault login", cfg.Provider)
			}

			if err := verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID); err != nil {
				return fmt.Errorf("git vault login: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), "GCP KMS round trip succeeded — this machine is authorized.")
			return err
		},
	}
}

// verifyGCPKMSRoundTrip encrypts and decrypts a fixed probe value against
// keyResourceID, returning an error (from gcpkms.Provider — see its
// friendlyLoginErr) if ADC is missing, IAM denies access, or the resource
// ID is malformed. Used by both `git vault login` and `git vault install`
// (to fail fast on a typo'd --key-resource-id).
func verifyGCPKMSRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := gcpkms.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(gcpkmsLoginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != gcpkmsLoginProbe {
		return fmt.Errorf("gcpkms: round trip returned unexpected plaintext")
	}
	return nil
}
