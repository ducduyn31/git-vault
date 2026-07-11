package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestNewLocalVault_ReturnsVaultAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	v, recipients, err := newLocalVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, recipients, 1)
	require.True(t, strings.HasPrefix(recipients[0], "local:"))
}

func TestVaultForProvider_Passphrase(t *testing.T) {
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")

	v, recipients, err := vaultForProvider(config.Config{Provider: passphrase.Name})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"passphrase:shared"}, recipients)
}

func TestVaultForProvider_GCPKMS(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	v, recipients, err := vaultForProvider(config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"gcpkms:projects/test/locations/global/keyRings/test/cryptoKeys/test"}, recipients)
}

func TestVaultForProvider_AzureKMS(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	v, recipients, err := vaultForProvider(config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"azurekms:https://test.vault.azure.net/keys/test-key/v1"}, recipients)
}

func TestVaultForProvider_UnknownProviderFails(t *testing.T) {
	_, _, err := vaultForProvider(config.Config{Provider: "bogus"})
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}

func TestNewVault_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	_, _, err := newVault()
	require.ErrorContains(t, err, "git vault install")
}

func TestNewVault_ReadsProviderFromConfig(t *testing.T) {
	chdirTemp(t)
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: passphrase.Name}))

	v, recipients, err := newVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"passphrase:shared"}, recipients)
}
