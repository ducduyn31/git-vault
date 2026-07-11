// Package awskms implements a keyservice.Provider backed by AWS KMS,
// authorized via whatever credentials the AWS SDK's default credential
// chain resolves on this machine (env vars, shared config/credentials
// file, or — for team key-sharing via SSO — a named profile set up with
// `aws configure sso`). Unlike internal/keyservice/local and
// internal/keyservice/passphrase, git-vault holds no key material of its
// own here: AWS IAM on the KMS key is the only access control, and
// git-vault never runs its own SSO device flow — `git vault login`
// (internal/cli/login.go) only ever shells out to the real `aws sso
// login`, and only with the user's explicit confirmation (or
// config.Config.AutoLogin). See
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md.
package awskms

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	sopskms "github.com/getsops/sops/v3/kms"
)

// Name is the provider name used in "awskms:<arn>" key identifiers (see
// internal/keyservice.Server).
const Name = "awskms"

// testHTTPClient and testCredentials override every MasterKey this
// package's Providers create. Set only via SetTestOverridesForTesting.
var (
	testHTTPClient  *http.Client
	testCredentials aws.CredentialsProvider
)

// SetTestOverridesForTesting points every Provider subsequently created
// by New at a fake AWS KMS HTTP server instead of real AWS
// infrastructure (see the awskmstest package), and supplies static
// credentials so no real credential chain lookup happens. It returns a
// function that restores the previous overrides — call it via defer. For
// use in tests only.
func SetTestOverridesForTesting(hc *http.Client, creds aws.CredentialsProvider) (restore func()) {
	prevHC, prevCreds := testHTTPClient, testCredentials
	testHTTPClient, testCredentials = hc, creds
	return func() { testHTTPClient, testCredentials = prevHC, prevCreds }
}

// Provider is backed by an AWS KMS key, identified per-call by keyID (a
// KMS ARN) rather than fixed at construction — the ARN lives in
// git-vault's repo-tracked config (internal/config.Config.KeyResourceID),
// not in this Provider. awsProfile names a local AWS CLI profile to
// resolve credentials from; empty means the SDK's default credential
// chain.
type Provider struct {
	awsProfile  string
	httpClient  *http.Client
	credentials aws.CredentialsProvider
}

// New returns a Provider using real AWS KMS, unless
// SetTestOverridesForTesting has redirected it to a fake server.
func New(awsProfile string) Provider {
	return Provider{awsProfile: awsProfile, httpClient: testHTTPClient, credentials: testCredentials}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the AWS KMS key named by
// keyID (an ARN of the form arn:aws:kms:<region>:<account>:key/<id>).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key := sopskms.NewMasterKeyFromArn(keyID, nil, p.awsProfile)
	p.apply(key)
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the AWS KMS key named by
// keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key := sopskms.NewMasterKeyFromArn(keyID, nil, p.awsProfile)
	p.apply(key)
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// apply configures key with this Provider's test overrides, if any.
func (p Provider) apply(key *sopskms.MasterKey) {
	if p.httpClient != nil {
		sopskms.NewHTTPClient(p.httpClient).ApplyToMasterKey(key)
	}
	if p.credentials != nil {
		sopskms.NewCredentialsProvider(p.credentials).ApplyToMasterKey(key)
	}
}

// ErrExpiredSSOSession is returned (via friendlyLoginErr) when the AWS
// SDK's cached SSO token has expired or is otherwise invalid
// (ssocreds.InvalidTokenError). It's a sentinel rather than just a
// message so callers — namely internal/cli/login.go — can detect this
// specific, fixable case with errors.Is and offer to run `aws sso login`
// themselves, instead of every caller re-parsing error text. Every other
// AWS credential failure (never configured, IAM denied) is passed
// through as-is — see
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md's
// Non-goals for why only this one case gets special handling.
var ErrExpiredSSOSession = errors.New("awskms: AWS SSO session has expired or is invalid — run `aws sso login` first")

// friendlyLoginErr rewrites an expired/invalid cached SSO token error
// into ErrExpiredSSOSession. ssocreds.InvalidTokenError is an exported
// type (unlike the ADC-missing case gcpkms handles by substring match),
// so errors.As reliably detects it through the AWS SDK's wrapped error
// chain. Any other error (e.g. IAM permission denied, malformed ARN, no
// credentials configured at all) is wrapped with op but otherwise passed
// through as-is.
func friendlyLoginErr(op string, err error) error {
	var invalidToken *ssocreds.InvalidTokenError
	if errors.As(err, &invalidToken) {
		return ErrExpiredSSOSession
	}
	return fmt.Errorf("awskms: %s: %w", op, err)
}
