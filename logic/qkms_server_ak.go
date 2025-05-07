package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *qkms_proto.ReadAccessKeyRequest) (*qkms_proto.ReadAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "read")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	reply := &qkms_proto.ReadAccessKeyReply{
		ErrorCode:   qkms_common.QKMS_ERROR_CODE_READ_AK_SUCCESS,
		NameSpace:   plain_cache_ak.NameSpace,
		Name:        plain_cache_ak.Name,
		AKPlaintext: plain_cache_ak.AKPlaintext,
		KeyType:     plain_cache_ak.KeyType,
		Environment: plain_cache_ak.Environment,
		Version:     plain_cache_ak.Version,
		ErrorMsg:    "success",
	}
	glog.Info(fmt.Sprintf("Read AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return reply, nil
}

func (server *QkmsRealServer) ReadReadableAccessKey(ctx context.Context, req *qkms_proto.ReadReadableAccessKeyRequest) (*qkms_proto.ReadReadableAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.ReadReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "read")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.ReadReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.ReadReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	readable_ak, err := qkms_crypto.Base64Decoding(plain_cache_ak.AKPlaintext)
	if err != nil {
		glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	reply := &qkms_proto.ReadReadableAccessKeyReply{
		ErrorCode:   qkms_common.QKMS_ERROR_CODE_READ_AK_SUCCESS,
		NameSpace:   plain_cache_ak.NameSpace,
		Name:        plain_cache_ak.Name,
		AKPlaintext: string(readable_ak),
		KeyType:     plain_cache_ak.KeyType,
		Environment: plain_cache_ak.Environment,
		Version:     plain_cache_ak.Version,
		ErrorMsg:    "success",
	}
	glog.Info(fmt.Sprintf("Read AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return reply, nil
}

func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *qkms_proto.GenerateAccessKeyRequest) (*qkms_proto.GenerateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GenerateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.GenerateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.GenerateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	plain_cache_ak, err := server.GenerateAKInternal(ctx, req.NameSpace, req.Name, req.KeyType, req.Environment, *ownerappkey, req.LifeTime, req.RotateDuration)
	if err != nil {
		glog.Info(fmt.Sprintf("Create AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.GenerateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))

	// need to ensure creator can read and write the ak
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "read", "allow")
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write", "allow")

	// register rotate ak task
	if plain_cache_ak.RotateDuration > 0 {
		glog.Info("Register rotate AK: %+v ", *plain_cache_ak)
		_, err := server.scheduler.Every(int(plain_cache_ak.RotateDuration)).Tag(plain_cache_ak.NameSpace + "-" + plain_cache_ak.Environment + "-" + plain_cache_ak.Name).Do(func() {
			err := server.RotateAccessKeyInternal(plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.KeyType, plain_cache_ak.Environment)
			if err != nil {
				glog.Error("Rotate AK failed: ", err.Error())
			}
		})
		if err != nil {
			glog.Error("Schedule Rotate AK failed: ", err.Error())
		}
	}

	return &qkms_proto.GenerateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS, ErrorMsg: "success"}, nil
}

func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *qkms_proto.CreateAccessKeyRequest) (*qkms_proto.CreateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	_, err = server.CreateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))

	// need to ensure creator can read and write the ak
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "read", "allow")
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write", "allow")

	return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS, ErrorMsg: "success"}, nil
}

func (server *QkmsRealServer) CreateReadableAccessKey(ctx context.Context, req *qkms_proto.CreateReadableAccessKeyRequest) (*qkms_proto.CreateReadableAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.CreateReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.CreateReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	_, err = server.CreateAKInternal(ctx, req.NameSpace, req.Name, qkms_crypto.Base64Encoding([]byte(req.AKPlaintext)), req.KeyType, req.Environment, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))

	// need to ensure creator can read and write the ak
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "read", "allow")
	server.CreateOrUpdateKeyAuthorizationPolicyInternal(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write", "allow")

	return &qkms_proto.CreateReadableAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS, ErrorMsg: "success"}, nil
}

func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *qkms_proto.UpdateAccessKeyRequest) (*qkms_proto.UpdateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, err
	}

	allow, err := server.CheckKAP(ctx, req.NameSpace, req.Name, req.Environment, *ownerappkey, "write")
	if err != nil {
		glog.Error(fmt.Sprintf("CheckKAP failed, req is %+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	if !allow {
		glog.Error(fmt.Sprintf("CheckKAP failed disallow, req is %+v", req.String()))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_NOT_AUTHORIZED}, err
	}

	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, err
	}
	if (plain_cache_ak.KeyType != req.KeyType) || (plain_cache_ak.Version != req.Version-1) {
		glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, "ak info mismatch"))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, errors.New("ak info mismatch")
	}

	_, err = server.UpdateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, plain_cache_ak.OwnerAppkey, req.Version)
	if err != nil {
		glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Update AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_SUCCESS, ErrorMsg: "success"}, nil
}

// todo , is this auth check needed ?
func (server *QkmsRealServer) GetAccessKeyIndexs(ctx context.Context, req *qkms_proto.GetAccessKeyIndexsRequest) (*qkms_proto.GetAccessKeyIndexsReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.GetAccessKeyIndexsReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GET_AK_INDEX_FAILED}, err
	}
	reply_aks, err := server.GetAccessKeyIndexsInternal(ctx, req.NameSpace)
	if err != nil {
		glog.Error(fmt.Sprintf("Get AK Index failed, Client appkey subject :%+v,err:%s", *ownerappkey, err.Error()))
		return &qkms_proto.GetAccessKeyIndexsReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_GET_AK_INDEX_FAILED}, err
	}
	reply := &qkms_proto.GetAccessKeyIndexsReply{
		ErrorCode:  qkms_common.QKMS_ERROR_CODE_GET_AK_INDEX_SUCCESS,
		AccessKeys: reply_aks,
		ErrorMsg:   "success",
	}
	glog.Info(fmt.Sprintf("Get AK Index Success, AK indexs :%+v,client appkey:%s", reply_aks, *ownerappkey))
	return reply, nil
}
