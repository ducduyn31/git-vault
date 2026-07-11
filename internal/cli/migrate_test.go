package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestMigrateCmd_LocalToPassphrase_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, local.Name)

	t.Setenv(passphrase.EnvVar, "correct horse battery staple")

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)

	// Prove it actually opens under the NEW provider, not just that the
	// command exited 0.
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_SameProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + local.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}

func TestMigrateCmd_MissingProviderFlagFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--provider is required")
}

func TestMigrateCmd_UnknownTargetProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=bogus"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}

func TestMigrateCmd_PassphraseTarget_MissingEnvVarFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "")
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, passphrase.EnvVar)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider, "config must not change when migrate fails fast")

	sealed, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Contains(t, string(sealed), "ENC[", "file must stay sealed under the old provider when migrate fails fast")
}

func TestMigrateCmd_NoTrackedFiles_UpdatesConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 0 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)
}

func TestMigrateCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}

func TestMigrateCmd_GCPKMSToGCPKMS_DifferentKey_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/key-b",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, gcpkms.Name, cfg.Provider)
	require.Equal(t, "projects/test/locations/global/keyRings/test/cryptoKeys/key-b", cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_GCPKMSToGCPKMS_SameKeyFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})
	err = cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")
}

func TestMigrateCmd_GCPKMSTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + gcpkms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestMigrateCmd_AWSKMSToAWSKMS_DifferentKey_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/key-a",
	})

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + awskms.Name,
		"--key-resource-id=arn:aws:kms:us-east-1:111111111111:key/key-b",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, awskms.Name, cfg.Provider)
	require.Equal(t, "arn:aws:kms:us-east-1:111111111111:key/key-b", cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_AWSKMSToAWSKMS_SameKeyFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/key-a",
	})

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + awskms.Name,
		"--key-resource-id=arn:aws:kms:us-east-1:111111111111:key/key-a",
	})
	err = cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")
}

func TestMigrateCmd_AWSKMSTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + awskms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}
