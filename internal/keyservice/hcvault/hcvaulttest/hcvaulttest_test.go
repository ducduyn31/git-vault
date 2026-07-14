package hcvaulttest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	srv := NewFakeServer("test-token")
	defer srv.Close()

	encBody, err := json.Marshal(map[string]any{"plaintext": "c29wcyBkYXRhIGtleQ=="}) // base64("sops data key")
	require.NoError(t, err)

	var encOut struct {
		Data struct{ Ciphertext string }
	}
	doFakeRequest(t, srv.URL, "test-token", "/v1/transit/encrypt/test-key", encBody, &encOut)
	require.NotEmpty(t, encOut.Data.Ciphertext)

	decBody, err := json.Marshal(map[string]any{"ciphertext": encOut.Data.Ciphertext})
	require.NoError(t, err)

	var decOut struct {
		Data struct{ Plaintext string }
	}
	doFakeRequest(t, srv.URL, "test-token", "/v1/transit/decrypt/test-key", decBody, &decOut)
	require.Equal(t, "c29wcyBkYXRhIGtleQ==", decOut.Data.Plaintext)
}

func TestFakeServer_WrongToken_Returns403(t *testing.T) {
	srv := NewFakeServer("test-token")
	defer srv.Close()

	encBody, err := json.Marshal(map[string]any{"plaintext": "c29wcyBkYXRhIGtleQ=="})
	require.NoError(t, err)

	resp := postFakeRequest(t, srv.URL, "wrong-token", "/v1/transit/encrypt/test-key", encBody)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	srv := NewFakeServer("")
	defer srv.Close()

	decBody, err := json.Marshal(map[string]any{"ciphertext": "not-a-real-wrapped-key"})
	require.NoError(t, err)

	resp := postFakeRequest(t, srv.URL, "", "/v1/transit/decrypt/test-key", decBody)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func postFakeRequest(t *testing.T, baseURL, token, path string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set(vaultapi.AuthHeaderName, token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func doFakeRequest(t *testing.T, baseURL, token, path string, body []byte, out any) {
	t.Helper()
	resp := postFakeRequest(t, baseURL, token, path, body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, out))
}
