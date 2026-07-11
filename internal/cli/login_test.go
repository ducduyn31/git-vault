package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)

func TestLoginCmd_GCPKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}))

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_GCPKMS_FailsWithoutReachableKMS(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "not-a-valid-resource-id",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func TestLoginCmd_LocalProviderRejected(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "does not use git vault login")
}

func TestLoginCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}

// fakeGcloud puts a stub "gcloud" script on PATH that exits with
// exitCode, and returns a function to restore the previous PATH.
func fakeGcloud(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake gcloud script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "gcloud")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func promptCmd(in, out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetIn(in)
	cmd.SetOut(out)
	return cmd
}

func TestAttemptGcloudLogin_NoGcloudOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
	require.Empty(t, out.String())
}

func TestAttemptGcloudLogin_Declined(t *testing.T) {
	fakeGcloud(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString("n\n"), out), false))
	require.Contains(t, out.String(), "Run `gcloud auth application-default login` now?")
}

func TestAttemptGcloudLogin_ConfirmedAndGcloudSucceeds(t *testing.T) {
	fakeGcloud(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
}

func TestAttemptGcloudLogin_ConfirmedButGcloudFails(t *testing.T) {
	fakeGcloud(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString("yes\n"), out), false))
}

func TestAttemptGcloudLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeGcloud(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString(""), out), true))
	require.Empty(t, out.String())
}

func TestAttemptGcloudLogin_AutoLoginStillNeedsGcloud(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptGcloudLogin(promptCmd(bytes.NewBufferString(""), out), true))
}

func TestLoginCmd_AWSKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/test",
	}))

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_AWSKMS_FailsWithoutReachableKMS(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "not-an-arn",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func TestLoginCmd_AzureKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	}))

	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_AzureKMS_FailsWithoutReachableVault(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "not-a-valid-url",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func fakeAwsCLI(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake aws script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "aws")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fakeAzCLI(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake az script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "az")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAttemptAWSSSOLogin_NoAWSCLIOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "", false))
	require.Empty(t, out.String())
}

func TestAttemptAWSSSOLogin_Declined(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("n\n"), out), "", false))
	require.Contains(t, out.String(), "Run `aws sso login` now?")
}

func TestAttemptAWSSSOLogin_ConfirmedAndCLISucceeds(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "", false))
}

func TestAttemptAWSSSOLogin_ConfirmedButCLIFails(t *testing.T) {
	fakeAwsCLI(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("yes\n"), out), "", false))
}

func TestAttemptAWSSSOLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString(""), out), "", true))
	require.Empty(t, out.String())
}

func TestAttemptAWSSSOLogin_AutoLoginStillNeedsCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString(""), out), "", true))
}

func TestAttemptAWSSSOLogin_IncludesProfileInPrompt(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "team-sso", false))
	require.Contains(t, out.String(), "aws sso login --profile team-sso")
}

func TestAttemptAzLogin_NoAzCLIOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
	require.Empty(t, out.String())
}

func TestAttemptAzLogin_Declined(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("n\n"), out), false))
	require.Contains(t, out.String(), "Run `az login` now?")
}

func TestAttemptAzLogin_ConfirmedAndCLISucceeds(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAzLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
}

func TestAttemptAzLogin_ConfirmedButCLIFails(t *testing.T) {
	fakeAzCLI(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("yes\n"), out), false))
}

func TestAttemptAzLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAzLogin(promptCmd(bytes.NewBufferString(""), out), true))
	require.Empty(t, out.String())
}

func TestAttemptAzLogin_AutoLoginStillNeedsCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString(""), out), true))
}
