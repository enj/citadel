package kms

import (
	"fmt"

	"github.com/enj/citadel/api/v1beta1"
	"github.com/enj/citadel/pkg/api"
	"github.com/enj/citadel/pkg/encryption"

	"golang.org/x/net/context"
)

const kmsAPIVersion = "v1beta1"

var apiVersionResponse = &v1beta1.VersionResponse{
	Version:        kmsAPIVersion,
	RuntimeName:    api.Name,
	RuntimeVersion: api.Version,
}

func NewKeyManagementService(service encryption.EncryptionService) v1beta1.KeyManagementServiceServer {
	return &kms{service: service}
}

var _ v1beta1.KeyManagementServiceServer = &kms{}

type kms struct {
	service encryption.EncryptionService
}

// TODO see if need to use context anywhere

func (k *kms) Version(ctx context.Context, req *v1beta1.VersionRequest) (*v1beta1.VersionResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	return apiVersionResponse, nil
}

func (k *kms) Decrypt(ctx context.Context, req *v1beta1.DecryptRequest) (*v1beta1.DecryptResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	plain, err := k.service.Decrypt(req.Cipher)
	if err != nil {
		return nil, err
	}
	return &v1beta1.DecryptResponse{
		Plain: plain,
	}, nil
}

func (k *kms) Encrypt(ctx context.Context, req *v1beta1.EncryptRequest) (*v1beta1.EncryptResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	cipher, err := k.service.Encrypt(req.Plain)
	if err != nil {
		return nil, err
	}
	return &v1beta1.EncryptResponse{
		Cipher: cipher,
	}, nil
}

func checkVersion(v string) error {
	if v != kmsAPIVersion {
		return fmt.Errorf("unsupported version %q, use %q", v, kmsAPIVersion)
	}
	return nil
}
