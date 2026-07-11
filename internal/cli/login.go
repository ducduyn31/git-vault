package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
)

// loginProbe is the fixed plaintext used to verify a KMS round trip. It
// carries no meaning beyond needing to survive Encrypt-then-Decrypt
// unchanged. Shared by every provider that uses git vault login.
const loginProbe = "git-vault-login-check"

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

			switch cfg.Provider {
			case gcpkms.Name:
				err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, cfg.AutoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "GCP KMS round trip succeeded — this machine is authorized.")
				return err
			case azurekms.Name:
				err = verifyAzureKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				if errors.Is(err, azurekms.ErrNoCredentials) && attemptAzLogin(cmd, cfg.AutoLogin) {
					err = verifyAzureKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Azure Key Vault round trip succeeded — this machine is authorized.")
				return err
			default:
				return fmt.Errorf("git vault login: provider %q does not use git vault login", cfg.Provider)
			}
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
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("gcpkms: round trip returned unexpected plaintext")
	}
	return nil
}

// attemptAzLogin tries to fix a missing-credentials failure
// (azurekms.ErrNoCredentials) by running `az login` — the one azurekms
// failure mode `login`/`install` can actually fix instead of just
// diagnosing. Mirrors attemptGcloudLogin's confirm-before-exec shape
// exactly, including the autoLogin (config.Config.AutoLogin) opt-out.
func attemptAzLogin(cmd *cobra.Command, autoLogin bool) bool {
	path, err := exec.LookPath("az")
	if err != nil {
		return false
	}

	if !autoLogin {
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "No Azure credentials found. Run `az login` now? [y/N] "); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	azCmd := exec.CommandContext(cmd.Context(), path, "login")
	azCmd.Stdin = cmd.InOrStdin()
	azCmd.Stdout = cmd.OutOrStdout()
	azCmd.Stderr = cmd.ErrOrStderr()
	return azCmd.Run() == nil
}

// verifyAzureKMSRoundTrip is verifyGCPKMSRoundTrip's Azure Key Vault
// equivalent — see its doc comment.
func verifyAzureKMSRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := azurekms.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("azurekms: round trip returned unexpected plaintext")
	}
	return nil
}
