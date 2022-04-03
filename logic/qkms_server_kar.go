package qkms_logic

import (
	"context"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"
)

func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *qkms_proto.GrantAccessKeyAuthorizationRequest) (*qkms_proto.GrantAccessKeyAuthorizationReply, error) {
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_INVALID}, err
	}
	erro_code, err := server.GrantKARInternal(ctx, req.NameSpace, req.Name, req.Environment, plain_cache_ak.OwnerAppkey, req.Appkey, req.Behavior)
	if err != nil {
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: erro_code}, err
	}
	return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_KAR_GRANTED}, nil
}
