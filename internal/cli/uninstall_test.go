package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
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

	runUninstallWithArgs(t, "--purge-keys", "--force")

	_, err = os.Stat(provider.IdentityPath)
	require.True(t, os.IsNotExist(err), "local identity file must be removed by --purge-keys")
	_, err = os.Stat(sessionPath)
	require.True(t, os.IsNotExist(err), "session cache must be removed by --purge-keys")
}

func TestUninstallCmd_PurgeAttrs_StripsGitVaultLinesOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	require.NoError(t, os.WriteFile(".gitattributes", []byte("*.bin binary\n"), 0o644))
	require.NoError(t, gitattr.Track(".gitattributes", "secret.yaml"))

	runUninstallWithArgs(t, "--purge-attrs")

	got, err := os.ReadFile(".gitattributes")
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n", string(got))
}

// trackPlaintextFile writes .git-vault.yaml directly, tracks "secret.yaml"
// and git-adds it as plaintext (no encrypt), so tests can exercise
// uninstall's plaintext-detection path without a real filter driver.
func trackPlaintextFile(t *testing.T, provider string) {
	t.Helper()
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: provider}))
	require.NoError(t, gitattr.Track(".gitattributes", "secret.yaml"))
	require.NoError(t, os.WriteFile("secret.yaml", []byte("password: hunter2\n"), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())
}

func TestUninstallCmd_WarnsAboutPlaintextTrackedFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	trackPlaintextFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "Warning")
}

func TestUninstallCmd_NoWarningWhenNothingTracked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.NotContains(t, out.String(), "Warning")
}

func TestUninstallCmd_NoWarningWhenTrackedFileIsSealed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.NotContains(t, out.String(), "Warning")
}

func TestUninstallCmd_PurgeAttrs_StillWarnsAboutPlaintextFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	trackPlaintextFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall", "--purge-attrs"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "Warning")

	got, err := os.ReadFile(".gitattributes")
	require.NoError(t, err)
	require.NotContains(t, string(got), "filter=git-vault")
}

func TestUninstallCmd_PurgeKeys_DeclineAbortsBeforeAnyMutation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	provider, err := local.New()
	require.NoError(t, err)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.Equal(t, "git-vault clean %f", gitConfigGet(t, false, "filter.git-vault.clean"))
	_, statErr := os.Stat(provider.IdentityPath)
	require.NoError(t, statErr, "local identity must survive a declined --purge-keys")
}

func TestUninstallCmd_PurgeKeys_ConfirmYes_Deletes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	provider, err := local.New()
	require.NoError(t, err)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.NoError(t, cmd.Execute())

	_, statErr := os.Stat(provider.IdentityPath)
	require.True(t, os.IsNotExist(statErr))
}

func TestUninstallCmd_PurgeKeys_SpecificWarningNamesSealedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "permanently unreadable")
}

func TestUninstallCmd_PurgeKeys_GenericWarningWhenNoSealedLocalFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.NotContains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "This deletes git-vault's local key material")
}

func TestUninstallCmd_PurgeKeysAndPurgeConfig_StillShowsSpecificWarning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys", "--purge-config"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	_, err := os.Stat(config.DefaultFileName)
	require.True(t, os.IsNotExist(err))
}
