package qkms_logic

import (
	"context"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"
)

func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *qkms_proto.ReadAccessKeyRequest) (*qkms_proto.ReadAccessKeyReply, error) {
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, "hxndg", "read")
	if err != nil {
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: error_code}, err
	}
	reply := &qkms_proto.ReadAccessKeyReply{
		ErrorCode:   qkms_common.QKMS_ERROR_CODE_READ_AK_SUCCESS,
		NameSpace:   plain_cache_ak.NameSpace,
		Name:        plain_cache_ak.Name,
		AKPlaintext: plain_cache_ak.AKPlaintext,
		KeyType:     plain_cache_ak.KeyType,
		Environment: plain_cache_ak.Environment,
		Version:     plain_cache_ak.Version,
	}

	return reply, nil
}

func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *qkms_proto.GenerateAccessKeyReply) (*qkms_proto.GenerateAccessKeyReply, error) {
	return nil, nil
}

func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *qkms_proto.CreateAccessKeyRequest) (*qkms_proto.CreateAccessKeyReply, error) {
	_, err := server.CreateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, "hxndg2")
	if err != nil {
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS}, nil
}

func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *qkms_proto.UpdateAccessKeyRequest) (*qkms_proto.UpdateAccessKeyReply, error) {
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, err
	}
	if (plain_cache_ak.KeyType != req.KeyType) || (plain_cache_ak.Version != req.Version-1) {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, err
	}
	error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, "hxndg", "write")
	if err != nil {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: error_code}, err
	}
	_, err = server.UpdateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, plain_cache_ak.OwnerAppkey, req.Version)
	if err != nil {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_FAILED}, err
	}
	return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_SUCCESS}, nil
}

func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *qkms_proto.RotateAccessKeyRequest) (*qkms_proto.RotateAccessKeyReply, error) {
	return nil, nil
}
