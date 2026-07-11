package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/session"
)

func runUninstallWithArgs(t *testing.T, extraArgs ...string) {
	t.Helper()
	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"uninstall"}, extraArgs...))
	require.NoError(t, cmd.Execute())
}

func TestUninstallCmd_UnsetsRepoLocalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	runUninstallWithArgs(t)

	_, err := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, err, "filter.git-vault.clean must be unset after uninstall")
}

func TestUninstallCmd_Global_UnsetsGlobalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstallWithArgs(t, "--global")

	runUninstallWithArgs(t, "--global")

	_, err := exec.Command("git", "config", "--global", "--get", "filter.git-vault.required").Output()
	require.Error(t, err, "filter.git-vault.required must be unset globally after uninstall --global")
}

func TestUninstallCmd_NotInstalled_IsNoop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	runUninstallWithArgs(t)
}

func TestUninstallCmd_LeavesConfigAndGitattributesByDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	require.NoError(t, gitattr.Track(".gitattributes", "secret.yaml"))

	runUninstallWithArgs(t)

	_, err := config.Load(config.DefaultFileName)
	require.NoError(t, err, config.DefaultFileName+" must survive a plain uninstall")
	_, err = os.Stat(".gitattributes")
	require.NoError(t, err, ".gitattributes must survive a plain uninstall")
}

func TestUninstallCmd_PurgeConfig_RemovesConfigFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	runUninstallWithArgs(t, "--purge-config")

	_, err := os.Stat(config.DefaultFileName)
	require.True(t, os.IsNotExist(err), "%s must be removed by --purge-config", config.DefaultFileName)
}

func TestUninstallCmd_PurgeKeys_RemovesLocalIdentitiesAndSession(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t) // generates a local identity as a side effect of resolving the recipient

	provider, err := local.New()
	require.NoError(t, err)
	_, statErr := os.Stat(provider.IdentityPath)
	require.NoError(t, statErr, "install must have created the local identity file")

	sessionPath, err := session.DefaultPath()
	require.NoError(t, err)
	require.NoError(t, session.Save(sessionPath, session.Session{Provider: local.Name}))

	runUninstallWithArgs(t, "--purge-keys")

	_, err = os.Stat(provider.IdentityPath)
	require.True(t, os.IsNotExist(err), "local identity file must be removed by --purge-keys")
	_, err = os.Stat(sessionPath)
	require.True(t, os.IsNotExist(err), "session cache must be removed by --purge-keys")
}
