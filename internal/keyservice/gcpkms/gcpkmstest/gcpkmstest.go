// Package gcpkmstest provides a fake GCP KMS server for testing code
// that uses internal/keyservice/gcpkms's Provider, without a real GCP
// project. It mirrors the pattern net/http/httptest uses for a fake HTTP
// server.
package gcpkmstest

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's gcpkms.MasterKey end-to-end without performing real
// cryptography or touching a real GCP project.
const marker = "fake-kms-wrapped:"

type fakeServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (fakeServer) Encrypt(_ context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return &kmspb.EncryptResponse{Ciphertext: append([]byte(marker), req.GetPlaintext()...)}, nil
}

func (fakeServer) Decrypt(_ context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	ciphertext := req.GetCiphertext()
	if !bytes.HasPrefix(ciphertext, []byte(marker)) {
		return nil, fmt.Errorf("gcpkmstest: ciphertext missing fake marker, got %q", ciphertext)
	}
	return &kmspb.DecryptResponse{Plaintext: ciphertext[len(marker):]}, nil
}

// NewFakeServer starts a fake GCP KMS gRPC server on a random local port
// and returns ClientOptions that redirect a gcpkms.MasterKey to it. The
// caller must invoke cleanup (e.g. via defer) to stop the server and
// close the client connection.
func NewFakeServer() (opts []option.ClientOption, cleanup func(), err error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("gcpkmstest: listen: %w", err)
	}
	srv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(srv, fakeServer{})
	go func() { _ = srv.Serve(lis) }()

	cleanup = func() { srv.Stop() }
	return []option.ClientOption{
		option.WithEndpoint(lis.Addr().String()),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	}, cleanup, nil
}
