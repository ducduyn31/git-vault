package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)

func newTestVault(t *testing.T) (*Vault, []string) {
	t.Helper()

	provider := &local.Provider{IdentityPath: filepath.Join(t.TempDir(), "identity.txt")}
	recipient, err := provider.Recipient()
	require.NoError(t, err)

	registry := keyservice.NewRegistry()
	require.NoError(t, registry.Register(provider))
	server := keyservice.NewServer(registry)

	return New(server), []string{"local:" + recipient}
}

func TestSealOpen_YAMLRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.yaml")
	original := "database:\n  password: hunter2\n  username: admin\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	require.Contains(t, string(sealed), "password: ENC[")
	require.Contains(t, string(sealed), "username: ENC[")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)

	var originalMap, roundTrippedMap map[string]interface{}
	require.NoError(t, yamlv3.Unmarshal([]byte(original), &originalMap))
	require.NoError(t, yamlv3.Unmarshal(opened, &roundTrippedMap))
	require.Equal(t, originalMap, roundTrippedMap)
}

func TestSealOpen_JSONRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.json")
	original := `{"password":"hunter2","username":"admin"}`
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)

	var originalMap, roundTrippedMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(original), &originalMap))
	require.NoError(t, json.Unmarshal(opened, &roundTrippedMap))
	require.Equal(t, originalMap, roundTrippedMap)
}

func TestSealOpen_DotenvRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), ".env.production")
	original := "API_KEY=supersecret\nDEBUG=true\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "supersecret")
	require.Contains(t, string(sealed), "API_KEY=ENC[")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestSealOpen_BinaryRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "key.pem")
	original := []byte("-----BEGIN PRIVATE KEY-----\nnotarealkey\n-----END PRIVATE KEY-----\n")
	require.NoError(t, os.WriteFile(path, original, 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "notarealkey")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, opened)
}

func TestSeal_NoRecipientsErrors(t *testing.T) {
	v, _ := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("a: b\n"), 0o644))

	require.Error(t, v.Seal(path, nil))
}

func TestOpen_TamperedMacFails(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.env")
	require.NoError(t, os.WriteFile(path, []byte("A=b\n"), 0o644))
	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	tampered := string(sealed) + "INJECTED=x\n"
	require.NoError(t, os.WriteFile(path, []byte(tampered), 0o644))

	require.Error(t, v.Open(path))
}
