package local

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
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

func TestProvider_Recipient_GeneratesHybridIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	recipient, err := p.Recipient()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(recipient, "age1pq1"), "expected a post-quantum hybrid recipient, got %q", recipient)
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
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "local", "identities")))
}

func TestNew_UsesDefaultIdentityPath(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p.IdentityPath, filepath.Join("git-vault", "local", "identities")))
}

func TestProvider_Rotate_OlderIdentityStillDecrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	oldRecipient, err := p.Recipient()
	require.NoError(t, err)

	ciphertext, err := p.Encrypt(context.Background(), oldRecipient, []byte("secret"))
	require.NoError(t, err)

	newRecipient, err := p.Rotate()
	require.NoError(t, err)
	require.NotEqual(t, oldRecipient, newRecipient)

	// Recipient() now reports the newest identity.
	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, newRecipient, current)

	// The file the old ciphertext names as its recipient still decrypts.
	got, err := p.Decrypt(context.Background(), oldRecipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)

	// New ciphertext targets the new recipient.
	newCiphertext, err := p.Encrypt(context.Background(), newRecipient, []byte("secret2"))
	require.NoError(t, err)
	got2, err := p.Decrypt(context.Background(), newRecipient, newCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret2"), got2)
}

func TestProvider_Rotate_TwiceKeepsBothOlderIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	r1, err := p.Recipient()
	require.NoError(t, err)
	c1, err := p.Encrypt(context.Background(), r1, []byte("v1"))
	require.NoError(t, err)

	r2, err := p.Rotate()
	require.NoError(t, err)
	c2, err := p.Encrypt(context.Background(), r2, []byte("v2"))
	require.NoError(t, err)

	r3, err := p.Rotate()
	require.NoError(t, err)

	got1, err := p.Decrypt(context.Background(), r1, c1)
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), got1)

	got2, err := p.Decrypt(context.Background(), r2, c2)
	require.NoError(t, err)
	require.Equal(t, []byte("v2"), got2)

	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, r3, current)
}

func TestProvider_Decrypt_UnknownKeyIDFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}
	_, err := p.Recipient()
	require.NoError(t, err)

	_, err = p.Decrypt(context.Background(), "age1thisdoesnotexist", []byte("ciphertext"))
	require.ErrorContains(t, err, "no stored identity")
}

func TestProvider_Identities_MigratesLegacyIdentityFile(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "identity.txt")
	newPath := filepath.Join(dir, "identities")

	legacy := &Provider{IdentityPath: legacyPath}
	legacyRecipient, err := legacy.Recipient()
	require.NoError(t, err)

	p := &Provider{IdentityPath: newPath}
	recipient, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, legacyRecipient, recipient, "must migrate the legacy identity, not generate a new one")

	// A subsequent Rotate must append to the migrated file, not overwrite it.
	newRecipient, err := p.Rotate()
	require.NoError(t, err)
	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, newRecipient, current)

	// The legacy identity is still present and still decrypts its own ciphertext.
	ciphertext, err := legacy.Encrypt(context.Background(), legacyRecipient, []byte("secret"))
	require.NoError(t, err)
	got, err := p.Decrypt(context.Background(), legacyRecipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestIdentityPathEnvVar_OverridesDefault(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom-identities")
	t.Setenv(IdentityPathEnvVar, custom)

	p, err := New()
	require.NoError(t, err)
	require.Equal(t, custom, p.IdentityPath)
}

func TestProvider_ExistingX25519OnlyFile_StillRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")

	// Simulate a pre-existing installation: an identities file written
	// before this change ever ran, containing only a classical X25519
	// identity, with no Hybrid identity present.
	oldID, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(oldID.String()+"\n"), 0o600))

	p := &Provider{IdentityPath: path}

	recipient, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, oldID.Recipient().String(), recipient, "must not silently generate a new identity when one already exists")
	require.False(t, strings.HasPrefix(recipient, "age1pq1"), "existing X25519-only file must not be force-migrated")

	ciphertext, err := p.Encrypt(context.Background(), recipient, []byte("secret"))
	require.NoError(t, err)
	got, err := p.Decrypt(context.Background(), recipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestProvider_MixedIdentityFile_RoundTripsBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")

	// Simulate the state right after one `git vault rotate` on a
	// pre-existing X25519-only install: one old classical line, one new
	// hybrid line, oldest first.
	oldID, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	newID, err := age.GenerateHybridIdentity()
	require.NoError(t, err)
	contents := oldID.String() + "\n" + newID.String() + "\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	p := &Provider{IdentityPath: path}

	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, newID.Recipient().String(), current, "Recipient must report the newest (last) entry")

	oldCiphertext, err := p.Encrypt(context.Background(), oldID.Recipient().String(), []byte("old-secret"))
	require.NoError(t, err)
	gotOld, err := p.Decrypt(context.Background(), oldID.Recipient().String(), oldCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("old-secret"), gotOld)

	newCiphertext, err := p.Encrypt(context.Background(), newID.Recipient().String(), []byte("new-secret"))
	require.NoError(t, err)
	gotNew, err := p.Decrypt(context.Background(), newID.Recipient().String(), newCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("new-secret"), gotNew)
}
