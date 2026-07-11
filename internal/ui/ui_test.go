package ui

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_InfoRendersCheckmarkNoAnsiOnBuffer(t *testing.T) {
	buf := &bytes.Buffer{}
	New(buf).Info("Tracking secrets/*.yaml")
	require.Equal(t, "✓ Tracking secrets/*.yaml\n", buf.String())
}

func TestError_RendersErrorPrefixNoAnsiOnBuffer(t *testing.T) {
	buf := &bytes.Buffer{}
	Error(buf, errors.New("git vault install: GIT_VAULT_PASSPHRASE not set"))
	require.Equal(t, "✗ Error: git vault install: GIT_VAULT_PASSPHRASE not set\n", buf.String())
}

func TestTable_RendersHeaderAndRows(t *testing.T) {
	buf := &bytes.Buffer{}
	Table(buf, [][2]string{
		{"secret.yaml", "plaintext"},
		{"other.yaml", "encrypted"},
		{"bad.yaml", "error: boom"},
	})

	out := buf.String()
	for _, want := range []string{
		"FILE", "STATE",
		"secret.yaml", "plaintext",
		"other.yaml", "encrypted",
		"bad.yaml", "error: boom",
	} {
		require.Contains(t, out, want)
	}
}
