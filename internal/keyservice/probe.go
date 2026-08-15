package keyservice

import (
	"context"
	"fmt"
)

// probe is the fixed plaintext used to verify a round trip. It carries no
// meaning beyond needing to survive Encrypt-then-Decrypt unchanged.
const probe = "git-vault-login-check"

// ProbeRoundTrip encrypts and decrypts a fixed probe against keyID,
// returning the provider's own error if credentials are missing, access is
// denied, or keyID is malformed. Callers use it to prove this machine can
// actually use a key before relying on it.
func ProbeRoundTrip(ctx context.Context, provider Provider, keyID string) error {
	ciphertext, err := provider.Encrypt(ctx, keyID, []byte(probe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != probe {
		return fmt.Errorf("%s: round trip returned unexpected plaintext", provider.Name())
	}
	return nil
}
