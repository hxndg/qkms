package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) CreateRole(ctx context.Context, req *qkms_proto.CreateRoleRequest) (*qkms_proto.CreateRoleReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_FAILED}, err
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "", "")
	if err != nil || !allow {
		return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_FAILED}, err
	}
	err = server.CreateRoleInternal(ctx, req.Name)
	if err != nil {
		return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_FAILED}, err
	}
	return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_SUCCESS, ErrorMsg: "success"}, nil
}
func (server *QkmsRealServer) GrantNameSpaceForRole(ctx context.Context, req *qkms_proto.GrantNameSpaceForRoleRequest) (*qkms_proto.GrantNameSpaceForRoleReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	err = server.CheckCertRevoked(ctx)
	if err != nil {
		return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "", "")
	if err != nil || !allow {
		return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	for index, namespace := range req.NameSpaces {
		err := server.GrantNameSpaceForRoleInternal(ctx, req.Role, namespace, req.Behavior)
		if err != nil {
			glog.Error(fmt.Sprintf("Grant namespace %s for %sth role %d failed, err: %s", namespace, req.Role, index, err.Error()))
			return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
		}
	}
	return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_SUCCESS, ErrorMsg: "success"}, nil
}
func (server *QkmsRealServer) GrantRoleForUser(ctx context.Context, req *qkms_proto.GrantRoleForUserRequest) (*qkms_proto.GrantRoleForUserReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	err = server.CheckCertRevoked(ctx)
	if err != nil {
		return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "", "")
	if err != nil || !allow {
		return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	grant, err := server.GrantRoleForUserInternal(ctx, req.Role, req.User)
	if err != nil || !grant {
		glog.Error(fmt.Sprintf("Grant role %s for user %s failed, err: %s", req.Role, req.User, err.Error()))
		return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_FAILED}, err
	}
	return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_SUCCESS, ErrorMsg: "success"}, nil
}
