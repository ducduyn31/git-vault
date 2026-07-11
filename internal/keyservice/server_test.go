package keyservice

import (
	"context"
	"errors"
	"testing"

	sopskeyservice "github.com/getsops/sops/v3/keyservice"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recordingProvider struct {
	name       string
	decryptErr error
}

func (p recordingProvider) Name() string { return p.name }

func (p recordingProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	return append([]byte("enc:"+keyID+":"), plaintext...), nil
}

func (p recordingProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if p.decryptErr != nil {
		return nil, p.decryptErr
	}
	return []byte("plaintext"), nil
}

func ageKey(recipient string) *sopskeyservice.Key {
	return &sopskeyservice.Key{
		KeyType: &sopskeyservice.Key_AgeKey{
			AgeKey: &sopskeyservice.AgeKey{Recipient: recipient},
		},
	}
}

func TestServer_Encrypt_DispatchesToProvider(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso"}))
	server := NewServer(registry)

	resp, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("sso:my-key"),
		Plaintext: []byte("secret"),
	})
	require.NoError(t, err)
	require.Equal(t, "enc:my-key:secret", string(resp.GetCiphertext()))
}

func TestServer_Decrypt_DispatchesToProvider(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso"}))
	server := NewServer(registry)

	resp, err := server.Decrypt(context.Background(), &sopskeyservice.DecryptRequest{
		Key:        ageKey("sso:my-key"),
		Ciphertext: []byte("enc:my-key:secret"),
	})
	require.NoError(t, err)
	require.Equal(t, "plaintext", string(resp.GetPlaintext()))
}

func TestServer_UnknownProvider_ReturnsNotFound(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("does-not-exist:my-key"),
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestServer_MalformedIdentifier_ReturnsInvalidArgument(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("no-colon-here"),
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServer_NonAgeKeyType_ReturnsInvalidArgument(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key: &sopskeyservice.Key{
			KeyType: &sopskeyservice.Key_PgpKey{PgpKey: &sopskeyservice.PgpKey{}},
		},
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServer_ProviderError_ReturnsPlainWrappedError(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso", decryptErr: errors.New("boom")}))
	server := NewServer(registry)

	_, err := server.Decrypt(context.Background(), &sopskeyservice.DecryptRequest{
		Key:        ageKey("sso:my-key"),
		Ciphertext: []byte("whatever"),
	})
	// Provider errors (e.g. gcpkms's friendly ADC-missing message) must
	// surface as plain errors, not gRPC status errors, so the friendly
	// text isn't buried under "rpc error: code = ... desc = ..." noise
	// on the encrypt/decrypt/clean/smudge path.
	require.ErrorContains(t, err, `provider "sso" decrypt: boom`)
	require.Equal(t, codes.Unknown, status.Code(err), "provider errors must not be gRPC status errors")
}
