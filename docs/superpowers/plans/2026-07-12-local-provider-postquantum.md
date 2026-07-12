# local provider post-quantum identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make git-vault's default `local` provider quantum-safe by generating age's built-in hybrid ML-KEM-768+X25519 identities instead of plain X25519, while old X25519 identities keep working forever.

**Architecture:** All changes are internal to `internal/keyservice/local/local.go`. The identity list widens from `[]*age.X25519Identity` to `[]age.Identity` so a repo can hold a mix of old and new identity types; a new private `recipientString` helper dispatches on concrete type since `age.Identity` doesn't expose `Recipient()` itself; `Encrypt` switches from a hardcoded `age.ParseX25519Recipient` call to the generic `age.ParseRecipients`, which already dispatches on the `age1`/`age1pq` prefix. No other package changes.

**Tech Stack:** Go 1.26, `filippo.io/age v1.3.1` (already pinned in `go.mod` — ships `HybridIdentity`/`HybridRecipient` in `pq.go`), `testify/require`.

## Global Constraints

- No changes to `internal/keyservice/provider.go`, `internal/cli/rotate.go`, `internal/vault`, or `.git-vault.yaml`'s schema (per spec's Non-goals).
- Old X25519 identities must keep decrypting their own ciphertext forever — never forced to migrate.
- No new dependency, no new CLI flag, no new config field, no new provider name.

---

### Task 1: Widen identity storage to `age.Identity` and add `recipientString` (no behavior change)

Pure refactor: still generates X25519 identities at this point. Confirms the type-widening doesn't break anything before Task 2 changes what gets generated.

**Files:**
- Modify: `internal/keyservice/local/local.go`
- Test: `internal/keyservice/local/local_test.go` (no edits this task — used only to confirm no regression)

**Interfaces:**
- Produces: `recipientString(id age.Identity) (string, error)` — used by Task 2's `Recipient()`/`Decrypt()` (already updated in this task) and by Task 3's new tests.
- Produces: `(*Provider).identities() ([]age.Identity, error)` — return type changes from `[]*age.X25519Identity`; same signature/behavior otherwise, consumed by `Recipient()`, `Decrypt()`, `Rotate()`.

- [ ] **Step 1: Run the existing suite to record the baseline**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS (all current tests green before touching anything)

- [ ] **Step 2: Add the `recipientString` helper**

In `internal/keyservice/local/local.go`, add this function after `Name()` (around line 68):

```go
// recipientString returns id's bech32 recipient encoding. age.Identity
// doesn't expose Recipient() itself — only the concrete *X25519Identity
// and *HybridIdentity types do, with different return types — so this
// dispatches on the two concrete types local.go supports.
func recipientString(id age.Identity) (string, error) {
	switch v := id.(type) {
	case *age.X25519Identity:
		return v.Recipient().String(), nil
	case *age.HybridIdentity:
		return v.Recipient().String(), nil
	default:
		return "", fmt.Errorf("local: unsupported identity type %T", id)
	}
}
```

- [ ] **Step 3: Widen `identities()`'s return type and use the new helper's type set**

Replace the `identities()` method (current lines 174-219) with:

```go
// identities loads every identity persisted at p.IdentityPath, migrating
// forward a pre-rename identity.txt sibling if one exists (see
// migrateLegacyIdentity), or generating and persisting a single fresh
// identity if neither exists yet. The list may mix *age.X25519Identity
// (pre-PQ) and *age.HybridIdentity (post-PQ) entries — see Rotate.
func (p *Provider) identities() ([]age.Identity, error) {
	data, err := os.ReadFile(p.IdentityPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("local: read identities: %w", err)
		}
		migrated, migrateErr := p.migrateLegacyIdentity()
		if migrateErr != nil {
			return nil, migrateErr
		}
		if !migrated {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return nil, fmt.Errorf("local: generate identity: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
				return nil, fmt.Errorf("local: create identity dir: %w", err)
			}
			if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("local: write identities: %w", err)
			}
			return []age.Identity{id}, nil
		}
		data, err = os.ReadFile(p.IdentityPath)
		if err != nil {
			return nil, fmt.Errorf("local: read identities: %w", err)
		}
	}

	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("local: parse identities: %w", err)
	}
	for _, id := range ids {
		switch id.(type) {
		case *age.X25519Identity, *age.HybridIdentity:
		default:
			return nil, fmt.Errorf("local: unsupported identity type %T in %s", id, p.IdentityPath)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("local: %s contains no identities", p.IdentityPath)
	}
	return ids, nil
}
```

(Note: `age.GenerateX25519Identity()` stays for now — this task only widens the *type*, Task 2 changes what gets *generated*.)

- [ ] **Step 4: Update `Recipient()` and `Decrypt()` to use `recipientString`**

Replace `Recipient()` (current lines 70-78) with:

```go
// Recipient returns the newest stored identity's recipient — a bech32
// age public key — generating a first identity if none are stored yet.
func (p *Provider) Recipient() (string, error) {
	ids, err := p.identities()
	if err != nil {
		return "", err
	}
	return recipientString(ids[len(ids)-1])
}
```

Replace `Decrypt()` (current lines 138-168) with:

```go
// Decrypt decrypts armored ciphertext (see Encrypt) using whichever
// stored identity's recipient matches keyID — the file's own sops
// metadata already names exactly which identity encrypted it, so this
// looks it up precisely rather than trying every stored identity.
func (p *Provider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	ids, err := p.identities()
	if err != nil {
		return nil, err
	}
	var match age.Identity
	for _, id := range ids {
		s, err := recipientString(id)
		if err != nil {
			return nil, err
		}
		if s == keyID {
			match = id
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("local: no stored identity matches recipient %q", keyID)
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, match)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	return plaintext, nil
}
```

- [ ] **Step 5: Run the suite to confirm no regression**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS (identical behavior — only the storage type widened, generation is still X25519)

- [ ] **Step 6: Commit**

```bash
git add internal/keyservice/local/local.go
git commit -m "refactor(local): widen identity storage to age.Identity

Prepares for mixed X25519/Hybrid identity lists — no behavior change,
identity generation still produces X25519."
```

---

### Task 2: Generate hybrid identities and switch `Encrypt` to generic recipient parsing

This is the actual behavior change: new identities (fresh install or `Rotate`) are now `age.HybridIdentity` (ML-KEM-768+X25519, `age1pq...`), and `Encrypt` parses whatever recipient type it's handed instead of assuming X25519.

**Files:**
- Modify: `internal/keyservice/local/local.go`
- Test: `internal/keyservice/local/local_test.go`

**Interfaces:**
- Consumes: `recipientString` from Task 1.
- Produces: fresh `Provider.Recipient()` now returns an `age1pq1...`-prefixed string; `Provider.Rotate()` now returns an `age1pq1...`-prefixed string. Task 3's tests rely on this prefix.

- [ ] **Step 1: Write the failing test for hybrid-by-default**

Add to `internal/keyservice/local/local_test.go`:

```go
func TestProvider_Recipient_GeneratesHybridIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	recipient, err := p.Recipient()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(recipient, "age1pq1"), "expected a post-quantum hybrid recipient, got %q", recipient)
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/keyservice/local/... -run TestProvider_Recipient_GeneratesHybridIdentity -v`
Expected: FAIL — `recipient` starts with `age1` (X25519) but not `age1pq1`

- [ ] **Step 3: Switch identity generation to hybrid**

In `identities()` (edited in Task 1), replace the `age.GenerateX25519Identity()` first-run branch:

```go
		if !migrated {
			id, err := age.GenerateHybridIdentity()
			if err != nil {
				return nil, fmt.Errorf("local: generate identity: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
				return nil, fmt.Errorf("local: create identity dir: %w", err)
			}
			if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("local: write identities: %w", err)
			}
			return []age.Identity{id}, nil
		}
```

In `Rotate()` (current lines 80-107), replace the generation call:

```go
// Rotate generates a fresh identity, appends and durably persists it
// alongside any existing ones (older identities are never removed — they
// stay valid for decrypting anything not yet re-sealed with the new one,
// including already-committed ciphertext), and returns its recipient.
// Persisted before returning, not after some later step, so a process
// that dies right after Rotate still leaves the new key durably on disk.
func (p *Provider) Rotate() (string, error) {
	if _, err := p.identities(); err != nil { // ensures the file/dir exist
		return "", err
	}

	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", fmt.Errorf("local: generate identity: %w", err)
	}
	f, err := os.OpenFile(p.IdentityPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("local: open identities file: %w", err)
	}
	if _, err := f.WriteString(id.String() + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("local: append identity: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("local: close identities file: %w", err)
	}
	return id.Recipient().String(), nil
}
```

- [ ] **Step 4: Run the full suite — expect a new, different failure**

Run: `go test ./internal/keyservice/local/... -v`
Expected: `TestProvider_Recipient_GeneratesHybridIdentity` now PASSes, but
`TestProvider_EncryptDecryptRoundTrip` (and other tests calling `Encrypt`
with a freshly-generated recipient) now FAIL with `local: parse recipient
"age1pq1...": ...` — `Encrypt` still hardcodes `age.ParseX25519Recipient`,
which rejects the `age1pq` prefix. This confirms Step 5 below is needed.

- [ ] **Step 5: Switch `Encrypt` to generic recipient parsing**

Add `"strings"` to the import block (`internal/keyservice/local/local.go`, current lines 18-28):

```go
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)
```

Replace `Encrypt()` (current lines 109-136) with:

```go
// Encrypt encrypts plaintext (a sops data key) to the recipient named by
// keyID using real age encryption, armored (see armor.NewWriter below) so
// the result is safe to store as a string inside a YAML/JSON document —
// raw binary age output is not valid UTF-8 and JSON in particular would
// silently corrupt it. age.ParseRecipients (rather than a hardcoded
// X25519 parse) dispatches on the age1/age1pq prefix, so this handles
// both classical and hybrid post-quantum recipients.
func (p *Provider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	recipients, err := age.ParseRecipients(strings.NewReader(keyID))
	if err != nil {
		return nil, fmt.Errorf("local: parse recipient %q: %w", keyID, err)
	}
	if len(recipients) != 1 {
		return nil, fmt.Errorf("local: expected exactly one recipient in %q, got %d", keyID, len(recipients))
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients[0])
	if err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 6: Run the full suite to confirm everything passes**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS — every test, including the new
`TestProvider_Recipient_GeneratesHybridIdentity` and the pre-existing
`TestProvider_EncryptDecryptRoundTrip`, `TestProvider_Rotate_*`,
`TestProvider_Identities_MigratesLegacyIdentityFile`.

- [ ] **Step 7: Commit**

```bash
git add internal/keyservice/local/local.go internal/keyservice/local/local_test.go
git commit -m "feat(local): generate hybrid ML-KEM-768+X25519 identities by default

New installs and every git vault rotate now generate post-quantum
hybrid identities (age1pq...) instead of plain X25519. Old X25519
identities keep decrypting their own ciphertext unchanged — Encrypt
now parses either recipient type via age.ParseRecipients."
```

---

### Task 3: Backward-compat and mixed-identity-file regression tests

Task 1+2's design already handles old-only and mixed identity files as an emergent property (`age.ParseIdentities` dispatches per line, `recipientString` dispatches per identity) — this task adds tests that pin that down as a guarantee, not an accident.

**Files:**
- Test: `internal/keyservice/local/local_test.go`

**Interfaces:**
- Consumes: `Provider.Encrypt`/`Decrypt`/`Recipient` (unchanged signatures, from `internal/keyservice/local/local.go`).

- [ ] **Step 1: Write the old-X25519-only backward-compat test**

Add to `internal/keyservice/local/local_test.go`:

```go
func TestProvider_ExistingX25519OnlyFile_StillRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")

	// Simulate a pre-existing installation: an identities file written
	// before this change ever ran, containing only a classical X25519
	// identity, with no Hybrid identity present.
	oldID, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(oldID.String()+"\n"), 0o600))

	p := &Provider{IdentityPath: path}

	recipient, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, oldID.Recipient().String(), recipient, "must not silently generate a new identity when one already exists")
	require.False(t, strings.HasPrefix(recipient, "age1pq1"), "existing X25519-only file must not be force-migrated")

	ciphertext, err := p.Encrypt(context.Background(), recipient, []byte("secret"))
	require.NoError(t, err)
	got, err := p.Decrypt(context.Background(), recipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}
```

- [ ] **Step 2: Add `"filippo.io/age"` and `"os"` to the test file's imports**

Update the import block at the top of `internal/keyservice/local/local_test.go`:

```go
import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)
```

- [ ] **Step 3: Run it to verify it passes**

Run: `go test ./internal/keyservice/local/... -run TestProvider_ExistingX25519OnlyFile_StillRoundTrips -v`
Expected: PASS (Task 1+2's generic identity handling already supports this — this test documents and locks in the guarantee)

- [ ] **Step 4: Write the mixed-identity-file test**

Add to `internal/keyservice/local/local_test.go`:

```go
func TestProvider_MixedIdentityFile_RoundTripsBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")

	// Simulate the state right after one `git vault rotate` on a
	// pre-existing X25519-only install: one old classical line, one new
	// hybrid line, oldest first.
	oldID, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	newID, err := age.GenerateHybridIdentity()
	require.NoError(t, err)
	contents := oldID.String() + "\n" + newID.String() + "\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	p := &Provider{IdentityPath: path}

	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, newID.Recipient().String(), current, "Recipient must report the newest (last) entry")

	oldCiphertext, err := p.Encrypt(context.Background(), oldID.Recipient().String(), []byte("old-secret"))
	require.NoError(t, err)
	gotOld, err := p.Decrypt(context.Background(), oldID.Recipient().String(), oldCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("old-secret"), gotOld)

	newCiphertext, err := p.Encrypt(context.Background(), newID.Recipient().String(), []byte("new-secret"))
	require.NoError(t, err)
	gotNew, err := p.Decrypt(context.Background(), newID.Recipient().String(), newCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("new-secret"), gotNew)
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/keyservice/local/... -run TestProvider_MixedIdentityFile_RoundTripsBoth -v`
Expected: PASS

- [ ] **Step 6: Run the full package suite one last time**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS — every test in the package, old and new.

- [ ] **Step 7: Run the whole module's tests to confirm no ripple effects**

Run: `go build ./... && go test ./...`
Expected: PASS — confirms `internal/cli/rotate.go` and anything else calling
`local.Provider` through the `keyservice.Provider` interface still compiles
and passes unchanged, since the interface signatures (`Name`/`Encrypt`/
`Decrypt`) never changed.

- [ ] **Step 8: Commit**

```bash
git add internal/keyservice/local/local_test.go
git commit -m "test(local): pin down old-X25519-only and mixed-identity-file behavior

Guards the backward-compat guarantee: a pre-existing X25519-only
identities file is never force-migrated, and a mixed file (post-rotate)
round-trips ciphertext under either identity."
```
