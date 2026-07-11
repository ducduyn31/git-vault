package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func gitConfigGet(t *testing.T, global bool, key string) string {
	t.Helper()
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, "--get", key)
	out, err := exec.Command("git", args...).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(old) })
	require.NoError(t, exec.Command("git", "init").Run())
}

func TestInstallCmd_SetsRepoLocalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install"})
	require.NoError(t, cmd.Execute())

	require.Equal(t, "git-vault clean %f", gitConfigGet(t, false, "filter.git-vault.clean"))
	require.Equal(t, "git-vault smudge %f", gitConfigGet(t, false, "filter.git-vault.smudge"))
	require.Equal(t, "true", gitConfigGet(t, false, "filter.git-vault.required"))
}

func TestInstallCmd_Global_SetsGlobalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--global"})
	require.NoError(t, cmd.Execute())

	require.Equal(t, "true", gitConfigGet(t, true, "filter.git-vault.required"))
}
