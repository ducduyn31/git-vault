package azurekmstest

import (
	"bytes"
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/require"
)

const (
	testVaultURL = "https://test.vault.azure.net"
	testKeyName  = "test-key"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v1")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	encResp, err := client.Encrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("sops data key"),
	}, nil)
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(encResp.Result))

	decResp, err := client.Decrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     encResp.Result,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(decResp.Result))
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v1")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	_, err = client.Decrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("not a real wrapped key"),
	}, nil)
	require.Error(t, err)
}

func TestFakeServer_GetKey_ReportsConfiguredCurrentVersion(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v7")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	resp, err := client.GetKey(context.Background(), testKeyName, "", nil)
	require.NoError(t, err)
	require.Equal(t, "v7", resp.Key.KID.Version())
	require.True(t, bytes.HasPrefix([]byte(*resp.Key.KID), []byte(testVaultURL)))
}
