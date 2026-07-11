package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestEncryptCmd_ThenDecryptCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	path := "secret.yaml"
	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	require.Contains(t, string(sealed), "password: ENC[")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", path})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestEncryptCmd_ThenDecryptCmd_PassphraseProvider_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)
	runInstallWithArgs(t, "--provider="+passphrase.Name)

	path := "secret.yaml"
	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	// sops embeds the recipient identifier in cleartext metadata (it isn't
	// secret) — asserting on "passphrase:shared" here, rather than just a
	// successful round-trip, is what actually proves the passphrase
	// provider was used and not local (which would also round-trip fine).
	require.Contains(t, string(sealed), "passphrase:shared")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", path})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestEncryptCmd_MissingConfigFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	path := "secret.yaml"
	require.NoError(t, os.WriteFile(path, []byte("password: hunter2\n"), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})

	err := encryptCmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}

func TestEncryptCmd_PrintsConfirmation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	path := "secret.yaml"
	require.NoError(t, os.WriteFile(path, []byte("password: hunter2\n"), 0o644))

	encryptCmd := NewRootCmd()
	out := &bytes.Buffer{}
	encryptCmd.SetOut(out)
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	require.Contains(t, out.String(), "Sealed secret.yaml")
}

func TestDecryptCmd_PrintsConfirmation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	path := "secret.yaml"
	require.NoError(t, os.WriteFile(path, []byte("password: hunter2\n"), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	decryptCmd := NewRootCmd()
	out := &bytes.Buffer{}
	decryptCmd.SetOut(out)
	decryptCmd.SetArgs([]string{"decrypt", path})
	require.NoError(t, decryptCmd.Execute())

	require.Contains(t, out.String(), "Opened secret.yaml")
}
