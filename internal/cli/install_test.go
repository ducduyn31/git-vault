package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
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

// setupTrackedEncryptedFile writes .git-vault.yaml directly (not via
// runInstall — install also sets filter.git-vault.* git config pointing at
// a real git-vault binary that isn't built under `go test`, which would
// make the "git add" below try to invoke it), tracks "secret.yaml", writes
// and git-adds it, then encrypts it under the given provider. Returns the
// plaintext it started from.
func setupTrackedEncryptedFile(t *testing.T, provider string) string {
	t.Helper()
	return setupTrackedEncryptedFileWithConfig(t, config.Config{Provider: provider})
}

// setupTrackedEncryptedFileWithConfig is setupTrackedEncryptedFile, but
// for providers (e.g. gcpkms) that need more than just a provider name
// persisted to .git-vault.yaml.
func setupTrackedEncryptedFileWithConfig(t *testing.T, cfg config.Config) string {
	t.Helper()
	require.NoError(t, config.Save(config.DefaultFileName, cfg))

	trackCmd := NewRootCmd()
	trackCmd.SetOut(&bytes.Buffer{})
	trackCmd.SetArgs([]string{"track", "secret.yaml"})
	require.NoError(t, trackCmd.Execute())

	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile("secret.yaml", []byte(original), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", "secret.yaml"})
	require.NoError(t, encryptCmd.Execute())

	return original
}

func TestInstallCmd_GCPKMS_WritesConfigAndValidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"install", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: gcpkms:projects/test/locations/global/keyRings/test/cryptoKeys/test")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, gcpkms.Name, cfg.Provider)
	require.Equal(t, "projects/test/locations/global/keyRings/test/cryptoKeys/test", cfg.KeyResourceID)
}

func TestInstallCmd_GCPKMS_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=" + gcpkms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestInstallCmd_GCPKMS_FailsWithoutReachableKMS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"install", "--provider=" + gcpkms.Name,
		"--key-resource-id=not-a-valid-resource-id",
	})

	err := cmd.Execute()
	require.Error(t, err)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails the KMS round trip")
}
