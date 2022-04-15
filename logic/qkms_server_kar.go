package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *qkms_proto.GrantAccessKeyAuthorizationRequest) (*qkms_proto.GrantAccessKeyAuthorizationReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_INVALID}, err
	}
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_INVALID}, err
	}
	// mainter can modify kar relation
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, plain_cache_ak.NameSpace, "write")
	if err != nil || !allow {
		if plain_cache_ak.OwnerAppkey != *ownerappkey {
			glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, "requester is not key owner"))
		}
	}
	erro_code, err := server.GrantKARInternal(ctx, req.NameSpace, req.Name, req.Environment, plain_cache_ak.OwnerAppkey, req.Appkey, req.Behavior)
	if err != nil {
		glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: erro_code}, err
	}
	glog.Info(fmt.Sprintf("Grant KAR success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_KAR_GRANTED}, nil
}
