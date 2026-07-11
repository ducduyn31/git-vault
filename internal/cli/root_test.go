package cli

import (
	"bytes"
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
