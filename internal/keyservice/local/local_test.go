package local

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProvider_Name(t *testing.T) {
	p := &Provider{}

	require.Equal(t, "local", p.Name())
}

func TestProvider_RecipientGeneratesAndPersistsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	p := &Provider{IdentityPath: path}

	recipient1, err := p.Recipient()
	require.NoError(t, err)
	require.NotEmpty(t, recipient1)

	// A second Provider pointed at the same file reuses the persisted
	// identity instead of generating a new one.
	p2 := &Provider{IdentityPath: path}
	recipient2, err := p2.Recipient()
	require.NoError(t, err)
	require.Equal(t, recipient1, recipient2)
}

func TestProvider_EncryptDecryptRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	p := &Provider{IdentityPath: path}
	recipient, err := p.Recipient()
	require.NoError(t, err)

	plaintext := []byte("a fake 32-byte sops data key!!!")

	ciphertext, err := p.Encrypt(context.Background(), recipient, plaintext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), string(plaintext))

	got, err := p.Decrypt(context.Background(), recipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestProvider_Decrypt_WrongIdentityFails(t *testing.T) {
	pathA := filepath.Join(t.TempDir(), "identity.txt")
	a := &Provider{IdentityPath: pathA}
	recipientA, err := a.Recipient()
	require.NoError(t, err)

	pathB := filepath.Join(t.TempDir(), "identity.txt")
	b := &Provider{IdentityPath: pathB}
	_, err = b.Recipient()
	require.NoError(t, err)

	ciphertext, err := a.Encrypt(context.Background(), recipientA, []byte("secret"))
	require.NoError(t, err)

	_, err = b.Decrypt(context.Background(), recipientA, ciphertext)
	require.Error(t, err)
}

func TestDefaultIdentityPath(t *testing.T) {
	path, err := DefaultIdentityPath()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "local", "identity.txt")))
}

func TestNew_UsesDefaultIdentityPath(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p.IdentityPath, filepath.Join("git-vault", "local", "identity.txt")))
}
