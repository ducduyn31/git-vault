package awskms

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
)

const testARN = "arn:aws:kms:us-east-1:111111111111:key/test"

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetTestOverridesForTesting(hc, creds)
	defer restore()

	p := New("")
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testARN, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testARN, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetTestOverridesForTesting(hc, creds)
	defer restore()

	p := New("")
	_, err = p.Decrypt(context.Background(), testARN, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_InvalidARNFails(t *testing.T) {
	p := New("")
	_, err := p.Encrypt(context.Background(), "not-an-arn", []byte("data"))
	require.ErrorContains(t, err, "no valid ARN found")
}

func TestFriendlyLoginErr_RewritesExpiredSSOSession(t *testing.T) {
	err := friendlyLoginErr("encrypt", fmt.Errorf("wrapped: %w", &ssocreds.InvalidTokenError{}))
	require.ErrorIs(t, err, ErrExpiredSSOSession)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "awskms: encrypt: permission denied")
}
