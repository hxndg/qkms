package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) CreateOrUpdateKeyAuthorizationPolicy(ctx context.Context, req *qkms_proto.CreateOrUpdateKeyAuthorizationPolicyRequest) (*qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_INVALID}, err
	}

	isAdmin, err := server.IsAdmin(ctx, *ownerappkey)
	if err != nil {
		return &qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !isAdmin {
		glog.Warning(fmt.Sprintf("GrantAdmin failed, ownerappkey: %s, isAdmin: %t", *ownerappkey, isAdmin))
		return &qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_NOT_AUTHORIZED}, nil
	}

	_, err = server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, req.UserAppkey, req.Action, req.Effect)
	if err != nil {
		glog.Error(fmt.Sprintf("CreateOrUpdateKeyAuthorizationPolicyInternal failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_FAILED}, err
	}

	glog.Info(fmt.Sprintf("Update KAP success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))

	// Reload the KAP
	if err := server.LoadKAP(); err != nil {
		glog.Error(fmt.Sprintf("LoadKAP failed, error: %s", err.Error()))
	}
	return &qkms_proto.CreateOrUpdateKeyAuthorizationPolicyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_SUCCESS, ErrorMsg: "success"}, nil
}
