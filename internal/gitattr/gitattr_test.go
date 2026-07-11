package gitattr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrack_CreatesFileAndAppendsLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Track(path, "secrets/*.yaml"))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "secrets/*.yaml filter=git-vault diff=git-vault -text\n", string(got))
}

func TestTrack_IdempotentWhenAlreadyTracked(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Track(path, "secrets/*.yaml"))
	require.NoError(t, Track(path, "secrets/*.yaml"))

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Len(t, patterns, 1)
}

func TestTracked_ParsesOnlyGitVaultFilterLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	content := "*.bin binary\n" +
		"secrets/*.yaml filter=git-vault diff=git-vault -text\n" +
		"*.lfs filter=lfs diff=lfs merge=lfs -text\n" +
		"config/*.env filter=git-vault diff=git-vault -text\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Equal(t, []string{"secrets/*.yaml", "config/*.env"}, patterns)
}

func TestTracked_MissingFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Empty(t, patterns)
}

func TestUntrack_RemovesGitVaultLinesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	content := "*.bin binary\n" +
		"secrets/*.yaml filter=git-vault diff=git-vault -text\n" +
		"*.lfs filter=lfs diff=lfs merge=lfs -text\n" +
		"config/*.env filter=git-vault diff=git-vault -text\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	require.NoError(t, Untrack(path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n*.lfs filter=lfs diff=lfs merge=lfs -text\n", string(got))
}

func TestUntrack_NoopWhenNothingTracked(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	require.NoError(t, os.WriteFile(path, []byte("*.bin binary\n"), 0o644))

	require.NoError(t, Untrack(path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n", string(got))
}

func TestUntrack_MissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Untrack(path))

	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err))
}
