package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
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

func runInstall(t *testing.T) {
	t.Helper()
	runInstallWithArgs(t)
}

func runInstallWithArgs(t *testing.T, extraArgs ...string) {
	t.Helper()
	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"install"}, extraArgs...))
	require.NoError(t, cmd.Execute())
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

func TestInstallCmd_Passphrase_WritesConfigAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"install", "--provider=passphrase"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: passphrase:shared")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)
}

func TestInstallCmd_Passphrase_MissingEnvVarFailsBeforeGitConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "")
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=passphrase"})

	err := cmd.Execute()
	require.ErrorContains(t, err, passphrase.EnvVar)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails fast")
}

func TestInstallCmd_UnknownProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=bogus"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}

func TestInstallCmd_DefaultProvider_WritesLocalConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install"})
	require.NoError(t, cmd.Execute())

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}
