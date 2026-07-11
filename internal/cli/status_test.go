package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)

func TestStatusCmd_NoGitattributes_ReportsNothingTracked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"status"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "No files tracked")
}

func TestStatusCmd_ReportsPlaintextThenEncrypted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	// Write .git-vault.yaml directly rather than calling runInstall(t):
	// install also registers filter.git-vault.{clean,smudge,required} in
	// git config, which would make the "git add" below shell out to a
	// real "git-vault" binary on PATH — not built by `go test`. status
	// only needs the config file so encrypt's newVault() below succeeds;
	// it doesn't need the filter driver wired up.
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	trackCmd := NewRootCmd()
	trackCmd.SetOut(&bytes.Buffer{})
	trackCmd.SetArgs([]string{"track", "secret.yaml"})
	require.NoError(t, trackCmd.Execute())

	require.NoError(t, os.WriteFile("secret.yaml", []byte("password: hunter2\n"), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())

	plainOut := &bytes.Buffer{}
	statusCmd := NewRootCmd()
	statusCmd.SetOut(plainOut)
	statusCmd.SetArgs([]string{"status"})
	require.NoError(t, statusCmd.Execute())
	require.Contains(t, plainOut.String(), "secret.yaml\tplaintext")

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", "secret.yaml"})
	require.NoError(t, encryptCmd.Execute())

	sealedOut := &bytes.Buffer{}
	statusCmd = NewRootCmd()
	statusCmd.SetOut(sealedOut)
	statusCmd.SetArgs([]string{"status"})
	require.NoError(t, statusCmd.Execute())
	require.Contains(t, sealedOut.String(), "secret.yaml\tencrypted")
}
