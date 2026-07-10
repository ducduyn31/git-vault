package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeal_ReturnsNotImplemented(t *testing.T) {
	v := New("unix:///tmp/git-vault-keyservice.sock")

	require.ErrorIs(t, v.Seal("secret.yaml"), ErrNotImplemented)
}

func TestOpen_ReturnsNotImplemented(t *testing.T) {
	v := New("unix:///tmp/git-vault-keyservice.sock")

	require.ErrorIs(t, v.Open("secret.yaml"), ErrNotImplemented)
}
