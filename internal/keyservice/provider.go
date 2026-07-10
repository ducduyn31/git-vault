// Package keyservice implements sops's KeyServiceServer extension point
// (see github.com/getsops/sops/v3/keyservice), dispatching Encrypt/Decrypt
// calls to a pluggable Provider rather than a fixed set of key backends
// compiled into sops itself. SSO is the first Provider; adding a new
// backend later means implementing this interface and registering it — no
// changes to internal/vault, internal/cli, or sops.
package keyservice

import "context"

// Provider performs Encrypt/Decrypt of a sops data key on behalf of one
// key backend (SSO, an internal KMS, Vault, ...). keyID is opaque to
// git-vault's Server — each Provider defines its own format for it.
type Provider interface {
	// Name identifies this provider in a "<provider>:<key-id>" identifier
	// (see Server in server.go).
	Name() string
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
}
