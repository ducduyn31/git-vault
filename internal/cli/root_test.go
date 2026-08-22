package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecute_Help(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--help"})

	require.NoError(t, cmd.Execute())
}

func TestVersionCmd_PrintsVersion(t *testing.T) {
	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"version"})

	require.NoError(t, cmd.Execute())
	require.Equal(t, "dev\n", out.String())
}

// Run from a subdirectory, git-vault must act on the repo root: git runs
// the clean/smudge filters there, so anything else silently diverges from
// what the filters see. The typed pattern is relative to the caller.
func TestRootCmd_FromSubdir_AnchorsToRepoRoot(t *testing.T) {
	chdirTemp(t)
	root, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Mkdir("sub", 0o755))
	require.NoError(t, os.Chdir(filepath.Join(root, "sub")))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"track", "*.yaml"})
	require.NoError(t, cmd.Execute())

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.Equal(t, root, cwd, "command must run from the repo root")

	attrs, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	require.NoError(t, err)
	require.Contains(t, string(attrs), "sub/*.yaml")
	require.NoFileExists(t, filepath.Join(root, "sub", ".gitattributes"))
}
