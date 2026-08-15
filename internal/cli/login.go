package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/provider"
)

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Verify this machine is authorized to use the repo's key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := provider.LoadConfig()
			if err != nil {
				return err
			}

			r, ok := provider.Remotes[cfg.Provider]
			if !ok {
				return fmt.Errorf("git vault login: provider %q does not use git vault login", cfg.Provider)
			}
			if err := verifyRoundTrip(cmd, cfg, true); err != nil {
				return fmt.Errorf("git vault login: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s round trip succeeded — this machine is authorized.\n", r.Display)
			return err
		},
	}
}

// verifyRoundTrip proves cfg's key is usable (provider.Probe), and with
// allowLogin set offers to run the provider's CLI login once when the
// failure is the kind a login fixes, then retries. login and install pass
// true; migrate passes false.
func verifyRoundTrip(cmd *cobra.Command, cfg config.Config, allowLogin bool) error {
	err := provider.Probe(cmd.Context(), cfg)
	if !allowLogin || err == nil {
		return err
	}

	r, ok := provider.Remotes[cfg.Provider]
	if ok && errors.Is(err, r.LoginErr) && attemptLogin(cmd, r, cfg) {
		err = provider.Probe(cmd.Context(), cfg)
	}
	return err
}

// attemptLogin runs the provider's login command (`gcloud auth
// application-default login`, `aws sso login`, ...) to fix the one
// credential failure it can fix, rather than just diagnosing it. Unless
// cfg.AutoLogin is set (a repo-committed opt-in), it asks for
// confirmation first: these commands open a browser and write credentials
// to disk, which needs consent from a subcommand that's otherwise
// read-only. Returns whether the login ran successfully, in which case
// the caller should retry; false (declined, binary not on PATH, or a
// nonzero exit) leaves the original error in place.
func attemptLogin(cmd *cobra.Command, r provider.Remote, cfg config.Config) bool {
	argv := r.LoginArgv(cfg)
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return false
	}

	if !cfg.AutoLogin {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s Run `%s` now? [y/N] ", r.LoginHint, strings.Join(argv, " ")); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	loginCmd := exec.CommandContext(cmd.Context(), path, argv[1:]...)
	loginCmd.Stdin = cmd.InOrStdin()
	loginCmd.Stdout = cmd.OutOrStdout()
	loginCmd.Stderr = cmd.ErrOrStderr()
	return loginCmd.Run() == nil
}
