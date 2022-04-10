package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (server *QkmsRealServer) CreateRole(ctx context.Context, req *qkms_proto.CreateRoleRequest) (*qkms_proto.CreateRoleReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("CreateRole failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to CreateRole, Client cert subject :%+v", subject))
		}
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "", "")
	if err != nil || !allow {
		return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_FAILED}, err
	}
	err = server.CreateRoleInternal(ctx, req.Name)
	if err != nil {
		return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_FAILED}, err
	}
	return &qkms_proto.CreateRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_ROLE_SUCCESS}, nil
}
func (server *QkmsRealServer) GrantNameSpaceForRole(ctx context.Context, req *qkms_proto.GrantNameSpaceForRoleRequest) (*qkms_proto.GrantNameSpaceForRoleReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("CreateRole failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to CreateRole, Client cert subject :%+v", subject))
		}
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
	return &qkms_proto.GrantNameSpaceForRoleReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_SUCCESS}, nil
}
func (server *QkmsRealServer) GrantRoleForUser(ctx context.Context, req *qkms_proto.GrantRoleForUserRequest) (*qkms_proto.GrantRoleForUserReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("CreateRole failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to CreateRole, Client cert subject :%+v", subject))
		}
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
	return &qkms_proto.GrantRoleForUserReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GRANT_NAMESPACE_FOR_ROLE_SUCCESS}, nil
}
