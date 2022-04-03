package qkms_logic

import (
	"context"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"
)

func (server *QkmsRealServer) CreateKeyEncryptionKey(ctx context.Context, req *qkms_proto.CreateKeyEncryptionKeyRequest) (*qkms_proto.CreateKeyEncryptionKeyReply, error) {
	_, err := server.CreateKEKInternal(ctx, req.NameSpace, req.Environment)
	if err != nil {
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_SUCCESS}, nil
}
