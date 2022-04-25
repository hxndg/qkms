package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"
	"strconv"

	"github.com/golang/glog"
)

/* only allow root to generate credentials */
func (server *QkmsRealServer) GenerateCredential(ctx context.Context, req *qkms_proto.GenerateCredentialRequest) (*qkms_proto.GenerateCredentialReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_FAILED}, err
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "user", "write")
	if err != nil || !allow {
		glog.Error(fmt.Sprintf("Create User failed, unauthorized user appkey:%s", *ownerappkey))
		return nil, err
	}

	plain_cache_user, err := server.GenerateCredentialInternal(context.Background(), server.ca_cert.Issuer.Organization[0], server.ca_cert.Issuer.Country[0], server.ca_cert.Issuer.Province[0], server.ca_cert.Issuer.Locality[0], req.Name, "rsa_4096")
	if err != nil {
		glog.Error(fmt.Sprintf("Create User failed, name:%s, appkey:%s, err:%s", req.Name, *ownerappkey, err.Error()))
		return &qkms_proto.GenerateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_FAILED}, err
	}

	reply := &qkms_proto.GenerateCredentialReply{
		ErrorCode: qkms_common.QKMS_ERROR_CODE_GENERATE_CREDENTIALS_SUCCESS,
		AppKey:    plain_cache_user.AppKey,
		Cert:      plain_cache_user.Cert,
		Key:       plain_cache_user.KeyPlaintext,
	}
	glog.Error(fmt.Sprintf("Create User success, name:%s, appkey:%s, cert:%s, key%s", req.Name, plain_cache_user.AppKey, plain_cache_user.Cert, plain_cache_user.KeyPlaintext))
	return reply, nil
}

func (server *QkmsRealServer) UpdateCredential(ctx context.Context, req *qkms_proto.UpdateCredentialRequest) (*qkms_proto.UpdateCredentialReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.UpdateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_FAILED}, err
	}
	user, err := LoadUser(ctx)
	if err != nil {
		return &qkms_proto.UpdateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_FAILED}, err
	}
	version, err := LoadVersion(ctx)
	if err != nil {
		return &qkms_proto.UpdateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_FAILED}, err
	}
	uint64_version, err := strconv.ParseUint(*version, 10, 64)
	if err != nil {
		return &qkms_proto.UpdateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_FAILED}, err
	}
	plain_cache_user, err := server.UpdateCredentialInternal(ctx, "Qube", "CN", "BeiJing", "QubeTest", *user, *ownerappkey, "rsa_4096", uint64_version+1)
	if err != nil {
		glog.Error(fmt.Sprintf("Update User failed, name:%s, appkey:%s, err:%s", *user, *ownerappkey, err.Error()))
		return &qkms_proto.UpdateCredentialReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_FAILED}, err
	}

	reply := &qkms_proto.UpdateCredentialReply{
		ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_CREDENTIALS_SUCCESS,
		Cert:      plain_cache_user.Cert,
		Key:       plain_cache_user.KeyPlaintext,
	}
	glog.Error(fmt.Sprintf("Create User success, name:%s, appkey:%s, cert:%s, key:%s", *user, plain_cache_user.AppKey, plain_cache_user.Cert, plain_cache_user.KeyPlaintext))
	return reply, nil
}
