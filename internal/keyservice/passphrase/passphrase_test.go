package passphrase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProvider_Name(t *testing.T) {
	p := New()

	require.Equal(t, "passphrase", p.Name())
}

func TestProvider_EncryptDecryptRoundTrip(t *testing.T) {
	t.Setenv(EnvVar, "correct horse battery staple")
	p := New()

	plaintext := []byte("a fake 32-byte sops data key!!!")

	ciphertext, err := p.Encrypt(context.Background(), KeyID, plaintext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), string(plaintext))

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestProvider_Decrypt_WrongPassphraseFails(t *testing.T) {
	t.Setenv(EnvVar, "correct horse battery staple")
	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	t.Setenv(EnvVar, "wrong passphrase")
	_, err = p.Decrypt(context.Background(), KeyID, ciphertext)
	require.Error(t, err)
}

func TestProvider_Encrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	p := New()

	_, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.ErrorContains(t, err, EnvVar)
}

func TestProvider_Decrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	p := New()

	_, err := p.Decrypt(context.Background(), KeyID, []byte("ciphertext"))
	require.ErrorContains(t, err, EnvVar)
}
