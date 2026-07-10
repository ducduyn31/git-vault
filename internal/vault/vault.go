// Package vault will wrap sops-as-a-library, configured to route key
// operations through git-vault's local keyservice (internal/keyservice).
// Per the scaffold design doc's non-goals, no real sops integration logic
// is implemented yet — Seal and Open are stubs. Follow-up work replaces
// them with real sops Encrypt/Decrypt tree calls (streaming, for
// clean/smudge).
package vault

import "errors"

// ErrNotImplemented is returned by every Vault operation until real sops
// integration lands.
var ErrNotImplemented = errors.New("vault: not implemented")

// Vault seals/opens files using sops, dialing KeyserviceAddr for key
// operations.
type Vault struct {
	KeyserviceAddr string
}

// New returns a Vault configured to use the keyservice at keyserviceAddr.
func New(keyserviceAddr string) *Vault {
	return &Vault{KeyserviceAddr: keyserviceAddr}
}

// Seal encrypts the file at path in place.
func (v *Vault) Seal(path string) error {
	return ErrNotImplemented
}

// Open decrypts the file at path in place.
func (v *Vault) Open(path string) error {
	return ErrNotImplemented
}
