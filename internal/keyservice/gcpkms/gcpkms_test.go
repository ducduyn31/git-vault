package gcpkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
)

const testResourceID = "projects/test/locations/global/keyRings/test/cryptoKeys/test"

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetClientOptionsForTesting(opts)
	defer restore()

	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testResourceID, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testResourceID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetClientOptionsForTesting(opts)
	defer restore()

	p := New()
	_, err = p.Decrypt(context.Background(), testResourceID, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_InvalidResourceIDFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-resource-id", []byte("data"))
	require.ErrorContains(t, err, "no valid resource ID")
}

func TestFriendlyLoginErr_RewritesMissingADCMessage(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("google: could not find default credentials. See https://example.com for more information"))
	require.ErrorContains(t, err, "gcloud auth application-default login")
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "gcpkms: encrypt: permission denied")
}
