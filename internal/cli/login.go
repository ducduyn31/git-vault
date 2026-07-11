package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
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
			case awskms.Name:
				err = verifyAWSKMSRoundTrip(cmd.Context(), cfg.KeyResourceID, cfg.AwsProfile)
				if errors.Is(err, awskms.ErrExpiredSSOSession) && attemptAWSSSOLogin(cmd, cfg.AwsProfile, cfg.AutoLogin) {
					err = verifyAWSKMSRoundTrip(cmd.Context(), cfg.KeyResourceID, cfg.AwsProfile)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "AWS KMS round trip succeeded — this machine is authorized.")
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

// attemptAWSSSOLogin tries to fix an expired/invalid cached SSO session
// (awskms.ErrExpiredSSOSession) by running `aws sso login`, scoped to
// awsProfile if set. It mirrors attemptGcloudLogin's confirm-before-exec
// shape exactly, including the autoLogin (config.Config.AutoLogin)
// opt-out. AWS's other credential failure modes (never configured,
// permission denied) are not handled here — see
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md's
// Non-goals.
func attemptAWSSSOLogin(cmd *cobra.Command, awsProfile string, autoLogin bool) bool {
	path, err := exec.LookPath("aws")
	if err != nil {
		return false
	}

	args := []string{"sso", "login"}
	if awsProfile != "" {
		args = append(args, "--profile", awsProfile)
	}
	displayCmd := "aws " + strings.Join(args, " ")

	if !autoLogin {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "AWS SSO session expired or missing. Run `%s` now? [y/N] ", displayCmd); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	awsCmd := exec.CommandContext(cmd.Context(), path, args...)
	awsCmd.Stdin = cmd.InOrStdin()
	awsCmd.Stdout = cmd.OutOrStdout()
	awsCmd.Stderr = cmd.ErrOrStderr()
	return awsCmd.Run() == nil
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

// verifyAWSKMSRoundTrip is verifyGCPKMSRoundTrip's AWS KMS equivalent —
// see its doc comment. awsProfile is passed through to awskms.New even
// when empty (meaning: use the default AWS credential chain).
func verifyAWSKMSRoundTrip(ctx context.Context, keyResourceID, awsProfile string) error {
	provider := awskms.New(awsProfile)
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("awskms: round trip returned unexpected plaintext")
	}
	return nil
}
