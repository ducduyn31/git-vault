package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestRotateCmd_Local_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	// Provider name is unchanged — rotate never writes .git-vault.yaml.
	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)

	// Prove the file actually opens under the NEW identity, not just that
	// the command exited 0.
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))

	// A second rotate still works — the identity list keeps growing.
	cmd2 := NewRootCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetArgs([]string{"rotate"})
	require.NoError(t, cmd2.Execute())
	require.Contains(t, out2.String(), "Rotated 1 file")
}

func TestRotateCmd_Passphrase_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "old passphrase")
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, passphrase.Name)

	restore := passphrase.SetPromptForTesting(func() (string, error) { return "new passphrase", nil })
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	// Now that the file is sealed under "new passphrase", the old env var
	// value alone can no longer open it...
	decryptWithOld := NewRootCmd()
	decryptWithOld.SetOut(&bytes.Buffer{})
	decryptWithOld.SetArgs([]string{"decrypt", "secret.yaml"})
	require.Error(t, decryptWithOld.Execute())

	// ...but the new one does.
	t.Setenv(passphrase.EnvVar, "new passphrase")
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestRotateCmd_Passphrase_MismatchedConfirmationFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "old passphrase")
	chdirTemp(t)
	setupTrackedEncryptedFile(t, passphrase.Name)

	calls := 0
	restore := passphrase.SetPromptForTesting(func() (string, error) {
		calls++
		if calls == 1 {
			return "first entry", nil
		}
		return "second entry", nil
	})
	defer restore()

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})
	err := cmd.Execute()
	require.ErrorContains(t, err, "did not match")

	// Nothing was touched: the file is still sealed under the original
	// passphrase.
	sealed, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Contains(t, string(sealed), "ENC[")
}

func TestRotateCmd_NoTrackedFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 0 file")
}

func TestRotateCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}

func TestRotateCmd_UnknownProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: "bogus"}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}

func TestRotateCmd_GCPKMS_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})

	sealedBefore, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	sealedAfter, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh KMS Encrypt call")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestRotateCmd_AWSKMS_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/test",
	})

	sealedBefore, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	sealedAfter, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh KMS Encrypt call")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestRotateCmd_AzureKMS_ReResolvesVersionAndRoundTrips(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	// The fake reports "v2" as current, simulating a key that was
	// rotated in Azure (out-of-band) since the file was originally
	// sealed under "v1".
	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v2")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	})

	sealedBefore, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	sealedAfter, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh Key Vault Encrypt call")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, "https://test.vault.azure.net/keys/test-key/v2", cfg.KeyResourceID, "rotate must persist the re-resolved current version")

	// The file's own embedded sops recipient must reference the NEW
	// version too — proving the re-seal actually moved the file onto v2,
	// not just that .git-vault.yaml's KeyResourceID was updated.
	require.Contains(t, string(sealedAfter), "azurekms:https://test.vault.azure.net/keys/test-key/v2")

	decryptCmd2 := NewRootCmd()
	decryptCmd2.SetOut(&bytes.Buffer{})
	decryptCmd2.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd2.Execute())

	opened2, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened2))
}
