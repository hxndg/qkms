package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

/* only allow root to generate credentials */
func (server *QkmsRealServer) GenerateCredential(ctx context.Context, req *qkms_proto.GenerateCredentialRequest) (*qkms_proto.GenerateCredentialReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_FAILED}, err
	}
	isAdmin, err := server.IsAdmin(ctx, *ownerappkey)
	if err != nil {
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !isAdmin {
		glog.Warning(fmt.Sprintf("GrantAdmin failed, ownerappkey: %s, isAdmin: %t", *ownerappkey, isAdmin))
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_NOT_AUTHORIZED}, nil
	}

	plain_cache_user, err := server.GenerateCredentialAndInsertDB(context.Background(), server.ca_cert.Issuer.Organization[0], server.ca_cert.Issuer.Country[0], server.ca_cert.Issuer.Province[0], server.ca_cert.Issuer.Locality[0], req.Name, "rsa_4096")
	if err != nil {
		glog.Error(fmt.Sprintf("Create User failed, name:%s, appkey:%s, err:%s", req.Name, *ownerappkey, err.Error()))
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_FAILED}, err
	}

	reply := &qkms_proto.GenerateCredentialReply{
		ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_SUCCESS,
		AppKey:    plain_cache_user.AppKey,
		Cert:      plain_cache_user.Cert,
		Key:       plain_cache_user.KeyPlaintext,
		ErrorMsg:  "success",
	}
	glog.Error(fmt.Sprintf("Create User success, name:%s, appkey:%s, cert:%s, key%s", req.Name, plain_cache_user.AppKey, plain_cache_user.Cert, plain_cache_user.KeyPlaintext))
	return reply, nil
}

func (server *QkmsRealServer) RevokeCredential(ctx context.Context, req *qkms_proto.RevokeCredentialRequest) (*qkms_proto.RevokeCredentialReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.RevokeCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_REVOKE_CREDENTIALS_FAILED}, err
	}

	isAdmin, err := server.IsAdmin(ctx, *ownerappkey)
	if err != nil {
		return &qkms_proto.RevokeCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !isAdmin {
		glog.Warning(fmt.Sprintf("GrantAdmin failed, ownerappkey: %s, isAdmin: %t", *ownerappkey, isAdmin))
		return &qkms_proto.RevokeCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_NOT_AUTHORIZED}, nil
	}
	_, err = server.RevokeCredentialInternal(ctx, req.AppKey)
	if err != nil {
		glog.Error(fmt.Sprintf("Remove User failed, appkey:%s, err:%s", *ownerappkey, err.Error()))
		return &qkms_proto.RevokeCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_REVOKE_CREDENTIALS_FAILED}, err
	}

	reply := &qkms_proto.RevokeCredentialReply{
		ErrorCode: qkms_common.QKMS_ERROR_CODE_REVOKE_CREDENTIALS_SUCCESS,
		ErrorMsg:  "success",
	}
	return reply, nil
}
