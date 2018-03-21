package kms

import (
	"github.com/enj/kms/api/v1beta1"
	"github.com/enj/kms/pkg/encryption/aes"
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

	aesService, err := aes.NewAESCBCService(cmdKEK)
	if err != nil {
		return err
	}

	kmService := kms.NewKeyManagementService(aesService)

	var serverOptions []grpc.ServerOption // TODO see if we need any server options
	grpcServer := grpc.NewServer(serverOptions...)
	v1beta1.RegisterKeyManagementServiceServer(grpcServer, kmService)

	if err := grpcServer.Serve(opts.listener); err != nil {
		return err
	}

	return nil
}
