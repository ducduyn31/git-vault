package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/gitattr"
)

func TestTrackCmd_AppendsPattern(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(old) }()

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"track", "secrets/*.yaml"})
	require.NoError(t, cmd.Execute())

	patterns, err := gitattr.Tracked(".gitattributes")
	require.NoError(t, err)
	require.Equal(t, []string{"secrets/*.yaml"}, patterns)
}
