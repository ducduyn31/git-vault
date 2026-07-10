package session

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	want := Session{
		Provider:  "sso",
		Token:     "abc123",
		ExpiresAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestExpired(t *testing.T) {
	s := Session{ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	require.True(t, s.Expired(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)))
	require.False(t, s.Expired(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)))
}

func TestLoad_MissingFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")

	_, err := Load(path)
	require.Error(t, err)
}

func TestDefaultPath_EndsUnderGitVaultCacheDir(t *testing.T) {
	path, err := DefaultPath()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "session.json")))
}
