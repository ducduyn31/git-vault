package passphrase

import (
	"bytes"
	"context"
	"fmt"
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

func TestProvider_Decrypt_OlderLineStillDecrypts(t *testing.T) {
	t.Setenv(EnvVar, "old passphrase")
	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Rotate: the env var now carries both lines, newest last. A file
	// still sealed under the older line must still open.
	t.Setenv(EnvVar, "old passphrase\nnew passphrase")
	p2 := New()
	got, err := p2.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestProvider_Encrypt_UsesNewestLine(t *testing.T) {
	t.Setenv(EnvVar, "old passphrase\nnew passphrase")
	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Only the newest line can open it.
	t.Setenv(EnvVar, "new passphrase")
	p2 := New()
	got, err := p2.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)

	t.Setenv(EnvVar, "old passphrase")
	p3 := New()
	_, err = p3.Decrypt(context.Background(), KeyID, ciphertext)
	require.Error(t, err)
}

func TestProvider_Encrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	})
	defer restore()
	p := New()

	_, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.ErrorContains(t, err, EnvVar)
}

func TestProvider_Decrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	})
	defer restore()
	p := New()

	_, err := p.Decrypt(context.Background(), KeyID, []byte("ciphertext"))
	require.ErrorContains(t, err, EnvVar)
}

func TestProvider_Decrypt_PromptedWhenEnvUnset(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) { return "typed passphrase", nil })
	defer restore()

	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestProvider_Ready_PromptsAndCachesForLaterCalls(t *testing.T) {
	t.Setenv(EnvVar, "")
	calls := 0
	restore := SetPromptForTesting(func() (string, error) {
		calls++
		return "typed passphrase", nil
	})
	defer restore()

	p := New()
	require.NoError(t, p.Ready())
	require.Equal(t, 1, calls, "Ready must prompt once")

	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)
	require.Equal(t, 1, calls, "a later Encrypt must reuse Ready's cached prompt, not prompt again")

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestProvider_Ready_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	})
	defer restore()

	err := New().Ready()
	require.ErrorContains(t, err, EnvVar)
}

func TestNewWithSecret_BypassesEnvVar(t *testing.T) {
	t.Setenv(EnvVar, "env passphrase")
	p := NewWithSecret("explicit passphrase")

	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Only the explicit secret opens it, not the env var's value.
	envP := New()
	_, err = envP.Decrypt(context.Background(), KeyID, ciphertext)
	require.Error(t, err)

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestPromptNewSecret_MatchingEntriesSucceed(t *testing.T) {
	restore := SetPromptForTesting(func() (string, error) { return "new passphrase", nil })
	defer restore()

	got, err := PromptNewSecret(&bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, "new passphrase", got)
}

func TestPromptNewSecret_MismatchedEntriesFail(t *testing.T) {
	calls := 0
	restore := SetPromptForTesting(func() (string, error) {
		calls++
		if calls == 1 {
			return "first entry", nil
		}
		return "second entry", nil
	})
	defer restore()

	_, err := PromptNewSecret(&bytes.Buffer{})
	require.ErrorContains(t, err, "did not match")
}
