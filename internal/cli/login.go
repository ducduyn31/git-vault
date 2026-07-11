package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

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

			err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
			if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, cfg.AutoLogin) {
				err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
			}
			if err != nil {
				return fmt.Errorf("git vault login: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), "GCP KMS round trip succeeded — this machine is authorized.")
			return err
		},
	}
}

// attemptGcloudLogin tries to fix a missing-ADC failure by running
// `gcloud auth application-default login` — the one gcpkms failure mode
// `login`/`install` can actually fix instead of just diagnosing. Unless
// autoLogin is set (config.Config.AutoLogin, a repo-committed
// opt-in), it asks for confirmation first: the command opens a browser
// and writes credentials to disk, which needs consent from a subcommand
// that's otherwise read-only. Returns whether gcloud ran successfully, in
// which case the caller should retry the round trip; false (declined, no
// gcloud on PATH, or a nonzero exit) leaves the original error in place.
func attemptGcloudLogin(cmd *cobra.Command, autoLogin bool) bool {
	path, err := exec.LookPath("gcloud")
	if err != nil {
		return false
	}

	if !autoLogin {
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "No Google credentials found. Run `gcloud auth application-default login` now? [y/N] "); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	gcloudCmd := exec.CommandContext(cmd.Context(), path, "auth", "application-default", "login")
	gcloudCmd.Stdin = cmd.InOrStdin()
	gcloudCmd.Stdout = cmd.OutOrStdout()
	gcloudCmd.Stderr = cmd.ErrOrStderr()
	return gcloudCmd.Run() == nil
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
