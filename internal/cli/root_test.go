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

func TestStubCommands_NotImplemented(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"login", []string{"login"}},
		{"install", []string{"install"}},
		{"encrypt", []string{"encrypt", "file.txt"}},
		{"decrypt", []string{"decrypt", "file.txt"}},
		{"clean", []string{"clean", "file.txt"}},
		{"smudge", []string{"smudge", "file.txt"}},
		{"status", []string{"status"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRootCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			require.ErrorContains(t, err, "not implemented in scaffold")
		})
	}
}
