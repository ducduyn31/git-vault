//go:build integration

// This file exercises Provider against a real HashiCorp Vault (in a
// container via testcontainers), covering the two things hcvaulttest's fake
// server structurally cannot: Transit's real versioned ciphertext format
// (vault:v1:…) across a real key rotation, and real token resolution from
// VAULT_TOKEN rather than SetTestOverridesForTesting. It needs a running
// container runtime, so it sits behind the `integration` build tag and out
// of the default `task test` / CI run — see `task test:integration`.
package hcvault

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
)

// vaultImage is pinned rather than :latest so a Vault release can't turn
// this test red on its own schedule.
const vaultImage = "hashicorp/vault:1.20.4"

const (
	rootToken = "root-test-token"
	keyName   = "git-vault-key"
)

// TestIntegration_RealVaultTransit runs one container for every subtest —
// they share it and run in order, since the rotation subtest deliberately
// builds on ciphertext the round-trip subtest produced.
func TestIntegration_RealVaultTransit(t *testing.T) {
	ctx := context.Background()

	ctr, err := tcvault.Run(ctx, vaultImage,
		tcvault.WithToken(rootToken),
		tcvault.WithInitCommand(
			"secrets enable transit",
			"write -f transit/keys/"+keyName,
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ctr.Terminate(ctx)) })

	addr, err := ctr.HttpHostAddress(ctx)
	require.NoError(t, err)
	keyID := addr + "/v1/transit/keys/" + keyName

	// No SetTestOverridesForTesting here: this is the real token resolution
	// path (VAULT_TOKEN, then ~/.vault-token) every fake-server test bypasses.
	t.Setenv("VAULT_TOKEN", rootToken)

	var v1Ciphertext []byte

	t.Run("round trip under key version 1", func(t *testing.T) {
		p := New()
		ciphertext, err := p.Encrypt(ctx, keyID, []byte("sops data key"))
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(string(ciphertext), "vault:v1:"),
			"expected a v1 Transit ciphertext, got %q", ciphertext)
		v1Ciphertext = ciphertext

		plaintext, err := p.Decrypt(ctx, keyID, ciphertext)
		require.NoError(t, err)
		require.Equal(t, "sops data key", string(plaintext))
	})

	t.Run("wrong token is reported as ErrNoValidToken", func(t *testing.T) {
		restore := SetTestOverridesForTesting("not-the-root-token")
		defer restore()

		_, err := New().Encrypt(ctx, keyID, []byte("sops data key"))
		require.ErrorIs(t, err, ErrNoValidToken)
	})

	t.Run("rotation keeps old ciphertext decryptable", func(t *testing.T) {
		require.NotEmpty(t, v1Ciphertext, "round-trip subtest must run first")

		code, out, err := ctr.Exec(ctx, []string{
			"vault", "write", "-f", "transit/keys/" + keyName + "/rotate",
		})
		require.NoError(t, err)
		rotateOut, err := io.ReadAll(out)
		require.NoError(t, err)
		require.Zero(t, code, "vault rotate failed: %s", rotateOut)

		p := New()

		// This is git-vault's rotation contract: pre-rotation ciphertext
		// still opens (so a repo isn't bricked the moment the key rotates),
		// while `git vault rotate` re-seals it onto the current version.
		plaintext, err := p.Decrypt(ctx, keyID, v1Ciphertext)
		require.NoError(t, err)
		require.Equal(t, "sops data key", string(plaintext))

		resealed, err := p.Encrypt(ctx, keyID, plaintext)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(string(resealed), "vault:v2:"),
			"expected a v2 Transit ciphertext after rotation, got %q", resealed)
	})
}
