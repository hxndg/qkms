package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) GrantAdmin(ctx context.Context, req *qkms_proto.GrantAdminRequest) (*qkms_proto.GrantAdminReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GrantAdminReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_AK_NOT_EXIST}, err
	}
	isAdmin, err := server.IsAdmin(ctx, *ownerappkey)
	if err != nil {
		return &qkms_proto.GrantAdminReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !isAdmin {
		glog.Warning(fmt.Sprintf("GrantAdmin failed, ownerappkey: %s, isAdmin: %t", *ownerappkey, isAdmin))
		return &qkms_proto.GrantAdminReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_NOT_AUTHORIZED}, nil
	}
	server.GrantAdminInternal(ctx, req.AppKey)
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(context.Background(), "*", "*", "*", req.AppKey, "read", "allow")
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(context.Background(), "*", "*", "*", req.AppKey, "write", "allow")

	// every kap updated, we need to load it
	if err := server.LoadKAP(); err != nil {
		glog.Error(fmt.Sprintf("LoadKAP failed, error: %s", err.Error()))
	}
	return &qkms_proto.GrantAdminReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_ADMIN_SUCCESS, ErrorMsg: "success"}, nil
}
