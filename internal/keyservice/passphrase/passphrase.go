// Package passphrase implements a keyservice.Provider backed by a shared
// secret read from an environment variable, encrypted with age's scrypt
// (password-based) recipient. Unlike internal/keyservice/local, the same
// passphrase can be distributed to a team out-of-band (e.g. a secrets
// manager or password vault) — there is no per-machine identity and no
// login flow, at the cost of weaker rotation and audit than a real
// SSO/KMS-backed provider.
//
// GIT_VAULT_PASSPHRASE holds one or more passphrases, one per line, oldest
// first and the current one last — a single-line value keeps working
// exactly as before. Encrypt always targets the newest line; Decrypt
// tries every line, so a file sealed under an older passphrase keeps
// opening for as long as that line is still present, e.g. during a
// `rotate` transition (see internal/cli/rotate.go).
package passphrase

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

// Name is the provider name used in "passphrase:<key-id>" key identifiers
// (see internal/keyservice.Server).
const Name = "passphrase"

// EnvVar is the environment variable this provider reads its passphrase(s)
// from, newline-separated, oldest first.
const EnvVar = "GIT_VAULT_PASSPHRASE"

// KeyID is the fixed key-id this provider uses: a passphrase-backed
// recipient is never versioned by key-id, only by how many lines
// EnvVar carries — see the package doc comment.
const KeyID = "shared"

// promptFn reads one passphrase interactively. A package-level variable so
// tests can replace it without a real terminal attached to stdin; see
// SetPromptForTesting.
var promptFn = defaultPrompt

// defaultPrompt prompts on stderr and reads hidden input from the
// controlling terminal. Returns an error immediately, without blocking,
// if stdin isn't a terminal.
func defaultPrompt() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	}
	if _, err := fmt.Fprint(os.Stderr, "git-vault passphrase: "); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("passphrase: read prompt: %w", err)
	}
	return string(b), nil
}

// SetPromptForTesting overrides the interactive prompt used by the
// env-var fallback and by PromptNewSecret. It returns a function that
// restores the previous prompt — call it via defer. For use in tests
// only, including from other packages that need to drive `rotate`
// (internal/cli) without a real terminal.
func SetPromptForTesting(fn func() (string, error)) (restore func()) {
	prev := promptFn
	promptFn = fn
	return func() { promptFn = prev }
}

// Provider is a Provider backed by the passphrase(s) in EnvVar, or by a
// single explicit secret (see NewWithSecret). It caches an interactively
// prompted secret so a command touching many tracked files only prompts
// once per process; the env var itself is re-read fresh on every call
// since that's cheap and needs no caching.
type Provider struct {
	explicit []string // set by NewWithSecret; bypasses EnvVar entirely
	prompted []string // cached result of an interactive prompt
}

// New returns a Provider reading from EnvVar (or prompting interactively
// if it's unset and stdin is a terminal).
func New() *Provider { return &Provider{} }

// NewWithSecret returns a Provider fixed to secret, bypassing EnvVar and
// any prompt entirely. Used by `rotate` (internal/cli) to build the "new"
// side of a rotation — passphrase has no local file to persist a rotated
// secret into, so the fresh secret only ever exists as this one in-memory
// value plus whatever the user does with it afterward.
func NewWithSecret(secret string) *Provider {
	return &Provider{explicit: []string{secret}}
}

// PromptNewSecret always prompts interactively (no EnvVar alternative,
// since generating a new passphrase is a deliberate one-off action, not
// routine CI traffic), entered twice to catch typos since there's no
// on-screen echo. out receives the two instructional lines; the prompt
// and hidden input themselves still go through promptFn.
func PromptNewSecret(out io.Writer) (string, error) {
	if _, err := fmt.Fprintln(out, "Enter new passphrase:"); err != nil {
		return "", err
	}
	first, err := promptFn()
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintln(out, "Confirm new passphrase:"); err != nil {
		return "", err
	}
	second, err := promptFn()
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passphrase: entries did not match")
	}
	return first, nil
}

func (p *Provider) Name() string { return Name }

// Encrypt encrypts plaintext (a sops data key) using real age scrypt
// encryption, armored (see armor.NewWriter below) so the result is safe
// to store as a string inside a YAML/JSON document — raw binary age
// output is not valid UTF-8 and JSON in particular would silently
// corrupt it. keyID is ignored: the secret(s) in scope are the only key
// material, and Encrypt always targets the newest one.
func (p *Provider) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	secrets, err := p.lookup()
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(secrets[len(secrets)-1])
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored ciphertext (see Encrypt) trying every secret
// in scope, newest first (scrypt's KDF is deliberately slow, and the
// common case post-rotation is that the newest passphrase is the one in
// use). keyID is ignored, for the same reason as Encrypt.
func (p *Provider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	secrets, err := p.lookup()
	if err != nil {
		return nil, err
	}
	identities := make([]age.Identity, len(secrets))
	for i, secret := range secrets {
		id, err := age.NewScryptIdentity(secret)
		if err != nil {
			return nil, fmt.Errorf("passphrase: %w", err)
		}
		identities[len(secrets)-1-i] = id
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, identities...)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	return plaintext, nil
}

// lookup resolves the secrets in scope: explicit (NewWithSecret) first,
// else EnvVar (re-read fresh every call — cheap, no caching needed), else
// an interactive prompt (cached in p.prompted so a process touching many
// files only prompts once).
func (p *Provider) lookup() ([]string, error) {
	if p.explicit != nil {
		return p.explicit, nil
	}
	if raw := os.Getenv(EnvVar); raw != "" {
		return splitSecrets(raw)
	}
	if p.prompted != nil {
		return p.prompted, nil
	}
	secret, err := promptFn()
	if err != nil {
		return nil, err
	}
	p.prompted = []string{secret}
	return p.prompted, nil
}

// splitSecrets parses EnvVar's newline-separated format, dropping blank
// lines.
func splitSecrets(raw string) ([]string, error) {
	var secrets []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			secrets = append(secrets, line)
		}
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("passphrase: %s not set", EnvVar)
	}
	return secrets, nil
}
