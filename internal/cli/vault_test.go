package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLocalVault_ReturnsVaultAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	v, recipients, err := newLocalVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, recipients, 1)
	require.True(t, strings.HasPrefix(recipients[0], "local:"))
}
