// Package vault wraps sops-as-a-library, configured to route key
// operations through git-vault's local keyservice (internal/keyservice),
// in-process — no network listener is involved. See
// docs/superpowers/specs/2026-07-11-vault-sops-integration-design.md.
package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	sopskeyservice "github.com/getsops/sops/v3/keyservice"

	"github.com/ducduyn31/git-vault/internal/keyservice"
)

// sopsVersion is written into new files' sops.version metadata field. It
// is a plain literal, not sops's own version.Version const, because that
// package imports github.com/urfave/cli purely for its CLI-version-check
// subcommand — a dependency this plan otherwise avoids. Keep this in sync
// with the github.com/getsops/sops/v3 version pinned in go.mod.
const sopsVersion = "3.13.2"

// Vault seals/opens files using sops, dispatching key operations to
// git-vault's own keyservice.Server in-process via
// sopskeyservice.NewCustomLocalClient.
type Vault struct {
	clients []sopskeyservice.KeyServiceClient
}

// New returns a Vault that dispatches key operations to server in-process.
func New(server *keyservice.Server) *Vault {
	return &Vault{
		clients: []sopskeyservice.KeyServiceClient{sopskeyservice.NewCustomLocalClient(server)},
	}
}

// Seal encrypts the file at path in place, creating a fresh sops tree
// keyed to recipients (opaque "<provider>:<key-id>" identifiers — see
// internal/keyservice.Server).
func (v *Vault) Seal(path string, recipients []string) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("vault: read %s: %w", path, err)
	}

	var out bytes.Buffer
	if err := v.SealStream(&out, bytes.NewReader(plaintext), FormatForPath(path), recipients); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// Open decrypts the file at path in place.
func (v *Vault) Open(path string) error {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("vault: read %s: %w", path, err)
	}

	var out bytes.Buffer
	if err := v.OpenStream(&out, bytes.NewReader(ciphertext), FormatForPath(path)); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// SealStream encrypts r (formatted per format), writing the sealed result
// to w. Used later by git's clean filter, which gets file content on
// stdin/stdout rather than a real path.
func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("vault: seal: no recipients provided")
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read plaintext: %w", err)
	}

	store := storeForFormat(format)
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return fmt.Errorf("vault: parse plaintext: %w", err)
	}

	keyGroup := make(sops.KeyGroup, len(recipients))
	for i, recipient := range recipients {
		keyGroup[i] = &age.MasterKey{Recipient: recipient}
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{keyGroup},
			Version:   sopsVersion,
		},
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(v.clients)
	if len(errs) > 0 {
		return fmt.Errorf("vault: generate data key: %w", errors.Join(errs...))
	}

	cipher := aes.NewCipher()
	unencryptedMac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	mac, err := cipher.Encrypt(unencryptedMac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("vault: encrypt mac: %w", err)
	}
	tree.Metadata.MessageAuthenticationCode = mac

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return fmt.Errorf("vault: emit encrypted file: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("vault: write ciphertext: %w", err)
	}
	return nil
}

// OpenStream decrypts r (formatted per format), writing the plaintext to
// w. Used later by git's smudge filter.
func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read ciphertext: %w", err)
	}

	store := storeForFormat(format)
	tree, err := store.LoadEncryptedFile(ciphertext)
	if err != nil {
		return fmt.Errorf("vault: parse ciphertext: %w", err)
	}

	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(v.clients, nil)
	if err != nil {
		return fmt.Errorf("vault: get data key: %w", err)
	}

	cipher := aes.NewCipher()
	computedMac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("vault: decrypt: %w", err)
	}
	fileMac, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("vault: decrypt mac: %w", err)
	}
	if fileMac != computedMac {
		return fmt.Errorf("vault: mac mismatch, file may have been tampered with")
	}

	out, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return fmt.Errorf("vault: emit plain file: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("vault: write plaintext: %w", err)
	}
	return nil
}
