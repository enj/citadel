package kms

import (
	"github.com/enj/kms/api/v1beta1"
	"github.com/enj/kms/pkg/encryption/prefix"
	"github.com/enj/kms/pkg/kek"
	"github.com/enj/kms/pkg/kms"

	"google.golang.org/grpc"
)

func Execute() error {
	opts, err := getOptions()
	if err != nil {
		return err
	}

	cmdKEK, err := kek.NewCommandKEKService(opts.command, opts.timeout)
	if err != nil {
		return err
	}
	defer cmdKEK.Stop()

	encryptionService, err := opts.mode.Handler(cmdKEK)
	if err != nil {
		return err
	}
	encryptionService = prefix.NewPrefixEncryption(opts.mode, encryptionService)

	kmService := kms.NewKeyManagementService(encryptionService)

	var serverOptions []grpc.ServerOption // TODO see if we need any server options
	grpcServer := grpc.NewServer(serverOptions...)
	v1beta1.RegisterKeyManagementServiceServer(grpcServer, kmService)

	if err := grpcServer.Serve(opts.listener); err != nil {
		return err
	}

	return nil
}
