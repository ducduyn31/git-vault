// Package hcvaulttest provides a fake HashiCorp Vault Transit server for
// testing code that uses internal/keyservice/hcvault's Provider, without a
// real Vault cluster. Unlike azurekmstest/awskmstest (which need a
// redirect transport because their SDK resolves a fixed cloud host), sops's
// hcvault.MasterKey is constructed directly from the --key-resource-id URL
// (via NewMasterKeyFromURI), so pointing that URL at this server's real
// httptest.Server address is enough — no custom http.Client override
// needed.
package hcvaulttest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's hcvault.MasterKey end-to-end without performing real cryptography
// or touching a real Vault cluster.
const marker = "fake-transit-wrapped:"

type encryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// NewFakeServer starts a fake Vault Transit HTTP server on a random local
// port. If expectedToken is non-empty, every request must carry an
// X-Vault-Token header matching it, or the server responds 403 (Vault's
// real permission-denied status for a missing/invalid/expired token). The
// caller must call the returned server's Close (e.g. via defer).
func NewFakeServer(expectedToken string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(w, r, expectedToken) {
			return
		}
		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeVaultError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeVaultData(w, map[string]any{"ciphertext": marker + req.Plaintext})
	})
	mux.HandleFunc("/v1/transit/decrypt/", func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(w, r, expectedToken) {
			return
		}
		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeVaultError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !strings.HasPrefix(req.Ciphertext, marker) {
			writeVaultError(w, http.StatusBadRequest, "hcvaulttest: ciphertext missing fake marker")
			return
		}
		writeVaultData(w, map[string]any{"plaintext": strings.TrimPrefix(req.Ciphertext, marker)})
	})
	return httptest.NewServer(mux)
}

func tokenOK(w http.ResponseWriter, r *http.Request, expectedToken string) bool {
	if expectedToken == "" || r.Header.Get(vaultapi.AuthHeaderName) == expectedToken {
		return true
	}
	writeVaultError(w, http.StatusForbidden, "permission denied")
	return false
}

func writeVaultData(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeVaultError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}
