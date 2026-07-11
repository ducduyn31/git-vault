package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	want := Config{
		Provider:      "gcpkms",
		IssuerURL:     "https://issuer.example.com",
		ClientID:      "git-vault-cli",
		KeyResourceID: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
		AutoLogin:     true,
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestLoad_MissingFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	_, err := Load(path)
	require.Error(t, err)
}

func TestLoad_MalformedYAMLReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	require.NoError(t, os.WriteFile(path, []byte("provider: [this is not valid: yaml"), 0o644))

	_, err := Load(path)
	require.Error(t, err)
}
