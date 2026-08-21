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

// Vault seals/opens files using sops, dispatching key operations to a
// keyservice.Server in-process via sopskeyservice.NewCustomLocalClient.
type Vault struct {
	clients []sopskeyservice.KeyServiceClient
}

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

// IsSealed reports whether the file at path currently holds a valid sops
// tree for its format (per FormatForPath) rather than plaintext. It only
// checks structure/metadata — no key material is needed, so this works
// even without a configured key provider.
func IsSealed(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("vault: read %s: %w", path, err)
	}
	_, err = storeForFormat(FormatForPath(path)).LoadEncryptedFile(data)
	return err == nil, nil
}

// SealStream encrypts r (formatted per format), writing the sealed result
// to w. Used by git's clean filter, which gets file content on
// stdin/stdout rather than a real path.
//
// If r is already a valid sops-encrypted document for format, it is
// written through to w unchanged instead of being sealed again — git can
// re-invoke clean on already-sealed content (e.g. during a merge/rebase
// re-apply), and sealing it a second time would double-wrap it.
func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error {
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read plaintext: %w", err)
	}
	return v.SealBytes(w, plaintext, format, recipients)
}

// SealBytes is SealStream for plaintext already in memory — the clean
// filter reads stdin itself, to compare against the staged blob before
// deciding to seal at all.
func (v *Vault) SealBytes(w io.Writer, plaintext []byte, format Format, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("vault: seal: no recipients provided")
	}

	store := storeForFormat(format)

	if _, err := store.LoadEncryptedFile(plaintext); err == nil {
		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("vault: write ciphertext: %w", err)
		}
		return nil
	}

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
// w. Used by git's smudge filter.
//
// If r has no sops metadata for format (e.g. a file committed before
// git-vault install was ever run), it is written through to w unchanged
// instead of erroring — only a failure decrypting an actual sops tree
// (bad key, tampered MAC) is a real error.
func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read ciphertext: %w", err)
	}

	store := storeForFormat(format)
	tree, err := store.LoadEncryptedFile(ciphertext)
	if err != nil {
		if _, err := w.Write(ciphertext); err != nil {
			return fmt.Errorf("vault: write plaintext: %w", err)
		}
		return nil
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

// IsSealedBytes reports whether data is a valid sops tree for format. It
// is the in-memory counterpart of IsSealed, for content that never hits
// disk (git filter streams).
func IsSealedBytes(data []byte, format Format) bool {
	_, err := storeForFormat(format).LoadEncryptedFile(data)
	return err == nil
}
