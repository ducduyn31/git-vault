package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanCmd_ThenSmudgeCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	original := "password: hunter2\n"

	cleanCmd := NewRootCmd()
	sealed := &bytes.Buffer{}
	cleanCmd.SetIn(strings.NewReader(original))
	cleanCmd.SetOut(sealed)
	cleanCmd.SetArgs([]string{"clean", "secret.yaml"})
	require.NoError(t, cleanCmd.Execute())

	require.NotContains(t, sealed.String(), "hunter2")
	require.Contains(t, sealed.String(), "password: ENC[")

	smudgeCmd := NewRootCmd()
	opened := &bytes.Buffer{}
	smudgeCmd.SetIn(bytes.NewReader(sealed.Bytes()))
	smudgeCmd.SetOut(opened)
	smudgeCmd.SetArgs([]string{"smudge", "secret.yaml"})
	require.NoError(t, smudgeCmd.Execute())

	require.Equal(t, original, opened.String())
}
