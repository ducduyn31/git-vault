package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptCmd_ThenDecryptCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), "secret.yaml")
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
