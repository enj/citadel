package kms

import (
	"fmt"

	"github.com/enj/kms/api/v1beta1"

	"golang.org/x/net/context"
)

const (
	version        = "v1beta1"
	runtimeName    = "clevis_kms"
	runtimeVersion = "0.0.1"
)

var apiVersionResponse = &v1beta1.VersionResponse{
	Version:        version,
	RuntimeName:    runtimeName,
	RuntimeVersion: runtimeVersion,
}

func NewClevisKMS() (v1beta1.KeyManagementServiceServer, error) {
	return &clevisKMS{}, nil
}

var _ v1beta1.KeyManagementServiceServer = &clevisKMS{}

type clevisKMS struct{} // TODO this may need to be public

// TODO see if need to use context anywhere

func (c *clevisKMS) Version(ctx context.Context, req *v1beta1.VersionRequest) (*v1beta1.VersionResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	return apiVersionResponse, nil
}

func (c *clevisKMS) Decrypt(ctx context.Context, req *v1beta1.DecryptRequest) (*v1beta1.DecryptResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	return &v1beta1.DecryptResponse{
		Plain: req.Cipher, // TODO actually do decryption
	}, nil
}

func (c *clevisKMS) Encrypt(ctx context.Context, req *v1beta1.EncryptRequest) (*v1beta1.EncryptResponse, error) {
	if err := checkVersion(req.Version); err != nil {
		return nil, err
	}
	return &v1beta1.EncryptResponse{
		Cipher: req.Plain, // TODO actually do encryption
	}, nil
}

func checkVersion(v string) error {
	if v != version {
		return fmt.Errorf("unsupported version %q, use %q", v, version)
	}
	return nil
}
