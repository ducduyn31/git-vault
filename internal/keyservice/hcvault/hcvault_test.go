package hcvault

import (
	"context"
	"errors"
	"fmt"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
)

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("test-token")
	defer srv.Close()
	restore := SetTestOverridesForTesting("test-token")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), keyID, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), keyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	_, err := p.Decrypt(context.Background(), keyID, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_EmptyKeyIDFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "", []byte("data"))
	require.ErrorContains(t, err, "key ID is required")
}

func TestProvider_Encrypt_MalformedURLFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-url", []byte("data"))
	require.Error(t, err)
}

func TestProvider_Encrypt_WrongTokenFails(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("expected-token")
	defer srv.Close()
	restore := SetTestOverridesForTesting("wrong-token")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	_, err := p.Encrypt(context.Background(), keyID, []byte("data"))
	require.ErrorIs(t, err, ErrNoValidToken)
}

func TestFriendlyLoginErr_RewritesPermissionDenied(t *testing.T) {
	// Wrapped with %w the same way sops's hcvault package wraps it
	// ("failed to encrypt sops data key to Vault transit backend '%s': %w"),
	// so this exercises the same errors.As unwrapping friendlyLoginErr relies on.
	respErr := &vaultapi.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}
	wrapped := fmt.Errorf("failed to encrypt sops data key to Vault transit backend 'transit/encrypt/test-key': %w", respErr)

	err := friendlyLoginErr("encrypt", wrapped)
	require.ErrorIs(t, err, ErrNoValidToken)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("network unreachable"))
	require.ErrorContains(t, err, "hcvault: encrypt: network unreachable")
}
