// Package azurekmstest provides a fake Azure Key Vault server for testing
// code that uses internal/keyservice/azurekms's Provider, without a real
// Azure tenant. It mirrors gcpkmstest's pattern, but uses the Azure SDK's
// own officially-supported fake transport (azkeys/fake) instead of a
// hand-rolled listener: fake.NewServerTransport implements
// policy.Transporter directly in-process, so there's no real network
// listener to start or clean up.
package azurekmstest

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys/fake"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's azkv.MasterKey end-to-end without performing real cryptography
// or touching a real Azure tenant.
const marker = "fake-kv-wrapped:"

// NewFakeServer returns a fake credential and ClientOptions that redirect
// an azkv.MasterKey (or a raw azkeys.Client) to an in-process fake Key
// Vault, without a real Azure tenant or network call. currentVersion is
// what the fake's GetKey handler reports as the key's latest version
// (queried with an empty version parameter, Key Vault's convention for
// "latest") — used by tests of azurekms.Provider.CurrentVersionURL (and
// `git vault rotate`) to simulate a key that was rotated out-of-band in
// Azure.
func NewFakeServer(vaultURL, keyName, currentVersion string) (azcore.TokenCredential, *azkeys.ClientOptions) {
	srv := fake.Server{
		Encrypt: func(_ context.Context, _ string, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.EncryptOptions) (resp azfake.Responder[azkeys.EncryptResponse], errResp azfake.ErrorResponder) {
			resp.SetResponse(http.StatusOK, azkeys.EncryptResponse{
				KeyOperationResult: azkeys.KeyOperationResult{
					Result: append([]byte(marker), parameters.Value...),
				},
			}, nil)
			return resp, errResp
		},
		Decrypt: func(_ context.Context, _ string, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (resp azfake.Responder[azkeys.DecryptResponse], errResp azfake.ErrorResponder) {
			if !bytes.HasPrefix(parameters.Value, []byte(marker)) {
				errResp.SetResponseError(http.StatusBadRequest, "BadParameter")
				return resp, errResp
			}
			resp.SetResponse(http.StatusOK, azkeys.DecryptResponse{
				KeyOperationResult: azkeys.KeyOperationResult{
					Result: parameters.Value[len(marker):],
				},
			}, nil)
			return resp, errResp
		},
		GetKey: func(_ context.Context, _ string, _ string, _ *azkeys.GetKeyOptions) (resp azfake.Responder[azkeys.GetKeyResponse], errResp azfake.ErrorResponder) {
			kid := azkeys.ID(fmt.Sprintf("%s/keys/%s/%s", vaultURL, keyName, currentVersion))
			resp.SetResponse(http.StatusOK, azkeys.GetKeyResponse{
				KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: &kid}},
			}, nil)
			return resp, errResp
		},
	}

	return &azfake.TokenCredential{}, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: fake.NewServerTransport(&srv)},
	}
}
