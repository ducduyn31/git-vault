// Package awskmstest provides a fake AWS KMS server for testing code
// that uses internal/keyservice/awskms's Provider, without a real AWS
// account. It mirrors gcpkmstest's pattern, but at the HTTP layer: sops's
// kms.MasterKey has no public endpoint-override hook (unlike GCP's
// option.ClientOption — MasterKey's baseEndpoint field is unexported,
// for sops's own tests only), so this works by giving MasterKey an
// *http.Client whose Transport redirects every request to a local
// httptest.Server, regardless of the region-derived AWS host the SDK
// resolves.
package awskmstest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's kms.MasterKey end-to-end without performing real cryptography
// or touching a real AWS account.
const marker = "fake-kms-wrapped:"

type encryptRequest struct {
	KeyId     string
	Plaintext []byte
}

type decryptRequest struct {
	CiphertextBlob []byte
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.Encrypt":
		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"CiphertextBlob": append([]byte(marker), req.Plaintext...),
			"KeyId":          req.KeyId,
		})
	case "TrentService.Decrypt":
		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.HasPrefix(req.CiphertextBlob, []byte(marker)) {
			http.Error(w, fmt.Sprintf("awskmstest: ciphertext missing fake marker, got %q", req.CiphertextBlob), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Plaintext": req.CiphertextBlob[len(marker):],
		})
	default:
		http.Error(w, fmt.Sprintf("awskmstest: unsupported X-Amz-Target %q", r.Header.Get("X-Amz-Target")), http.StatusBadRequest)
	}
}

// redirectTransport rewrites every outbound request's scheme/host to
// point at the fake server, regardless of what host the AWS SDK resolved
// the request to (kms.<region>.amazonaws.com).
type redirectTransport struct {
	scheme, host string
}

func (t redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.scheme
	req.URL.Host = t.host
	req.Host = t.host
	return http.DefaultTransport.RoundTrip(req)
}

// NewFakeServer starts a fake AWS KMS HTTP server on a random local port
// and returns an *http.Client that redirects every request to it, plus
// static credentials so no real AWS credential chain lookup happens. The
// caller must invoke cleanup (e.g. via defer) to stop the server.
func NewFakeServer() (httpClient *http.Client, credentials aws.CredentialsProvider, cleanup func(), err error) {
	srv := httptest.NewServer(http.HandlerFunc(handler))
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		return nil, nil, nil, fmt.Errorf("awskmstest: parse server URL: %w", err)
	}

	httpClient = &http.Client{Transport: redirectTransport{scheme: u.Scheme, host: u.Host}}
	credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
	})
	return httpClient, credentials, srv.Close, nil
}
