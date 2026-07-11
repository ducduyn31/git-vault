package keyservice

import (
	"context"
	"fmt"
	"strings"

	sopskeyservice "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements sops's KeyServiceServer by dispatching to git-vault's
// own pluggable Provider registry.
//
// sops's keyservice protocol has a fixed, closed set of key types (kms,
// pgp, gcp_kms, azure_keyvault, vault, age) with no extension point
// for a new one without forking sops. git-vault reuses the age key type's
// `recipient` string as an opaque carrier: it is never a real age
// recipient, only a "<provider-name>:<key-id>" identifier that Server
// parses and routes to the matching Provider. Any other key type is
// rejected — git-vault only ever writes age-shaped entries for its own
// provider keys.
type Server struct {
	sopskeyservice.UnimplementedKeyServiceServer
	registry *Registry
}

// NewServer returns a Server that dispatches to registry.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry}
}

var _ sopskeyservice.KeyServiceServer = (*Server)(nil)

func (s *Server) Encrypt(ctx context.Context, req *sopskeyservice.EncryptRequest) (*sopskeyservice.EncryptResponse, error) {
	provider, keyID, err := s.resolve(req.GetKey())
	if err != nil {
		return nil, err
	}
	ciphertext, err := provider.Encrypt(ctx, keyID, req.GetPlaintext())
	if err != nil {
		return nil, fmt.Errorf("provider %q encrypt: %w", provider.Name(), err)
	}
	return &sopskeyservice.EncryptResponse{Ciphertext: ciphertext}, nil
}

func (s *Server) Decrypt(ctx context.Context, req *sopskeyservice.DecryptRequest) (*sopskeyservice.DecryptResponse, error) {
	provider, keyID, err := s.resolve(req.GetKey())
	if err != nil {
		return nil, err
	}
	plaintext, err := provider.Decrypt(ctx, keyID, req.GetCiphertext())
	if err != nil {
		return nil, fmt.Errorf("provider %q decrypt: %w", provider.Name(), err)
	}
	return &sopskeyservice.DecryptResponse{Plaintext: plaintext}, nil
}

// resolve extracts "<provider>:<key-id>" from the age key's recipient
// field and looks up the matching Provider.
func (s *Server) resolve(key *sopskeyservice.Key) (Provider, string, error) {
	ageKey := key.GetAgeKey()
	if ageKey == nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "git-vault only handles age-shaped key entries, got %T", key.GetKeyType())
	}

	name, keyID, ok := strings.Cut(ageKey.GetRecipient(), ":")
	if !ok {
		return nil, "", status.Errorf(codes.InvalidArgument, "malformed git-vault key identifier %q, want \"<provider>:<key-id>\"", ageKey.GetRecipient())
	}

	provider, found := s.registry.Get(name)
	if !found {
		return nil, "", status.Errorf(codes.NotFound, "no provider registered for %q", name)
	}
	return provider, keyID, nil
}
