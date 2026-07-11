package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
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
