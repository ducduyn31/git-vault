package azurekms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
)

const (
	testVaultURL = "https://test.vault.azure.net"
	testKeyName  = "test-key"
	testKeyURL   = testVaultURL + "/keys/" + testKeyName + "/v1"
)

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v1")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testKeyURL, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testKeyURL, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v1")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	_, err := p.Decrypt(context.Background(), testKeyURL, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_MissingVersionFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), testVaultURL+"/keys/"+testKeyName, []byte("data"))
	require.ErrorContains(t, err, "not a valid Key Vault key URL")
}

func TestProvider_Encrypt_MalformedURLFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-url", []byte("data"))
	require.ErrorContains(t, err, "not a valid Key Vault key URL")
}

func TestProvider_CurrentVersionURL_ResolvesLatest(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v2")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	resolved, err := p.CurrentVersionURL(context.Background(), testKeyURL)
	require.NoError(t, err)
	require.Equal(t, testVaultURL+"/keys/"+testKeyName+"/v2", resolved)
}

func TestFriendlyLoginErr_RewritesMissingCredentialsMessage(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("failed to get Azure token credential to encrypt data: DefaultAzureCredential: failed to acquire a token.\nAttempted credentials:\n\tEnvironmentCredential: missing environment variable AZURE_TENANT_ID"))
	require.ErrorIs(t, err, ErrNoCredentials)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "azurekms: encrypt: permission denied")
}
