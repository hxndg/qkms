package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
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
	// if user is mainter of namespace, allow read
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, plain_cache_ak.NameSpace, "read")
	if err != nil || !allow {
		error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, *ownerappkey, qkms_common.QKMS_BEHAVIOR_READ)
		if err != nil {
			glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: error_code}, err
		}
	}
	reply := &qkms_proto.ReadAccessKeyReply{
		ErrorCode:   qkms_common.QKMS_ERROR_CODE_READ_AK_SUCCESS,
		NameSpace:   plain_cache_ak.NameSpace,
		Name:        plain_cache_ak.Name,
		AKPlaintext: plain_cache_ak.AKPlaintext,
		KeyType:     plain_cache_ak.KeyType,
		Environment: plain_cache_ak.Environment,
		Version:     plain_cache_ak.Version,
	}
	glog.Info(fmt.Sprintf("Read AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return reply, nil
}

func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *qkms_proto.GenerateAccessKeyReply) (*qkms_proto.GenerateAccessKeyReply, error) {
	return nil, nil
}

func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *qkms_proto.CreateAccessKeyRequest) (*qkms_proto.CreateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}

	_, err = server.CreateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS}, nil
}

func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *qkms_proto.UpdateAccessKeyRequest) (*qkms_proto.UpdateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH}, err
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
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, plain_cache_ak.NameSpace, "write")
	if err != nil || !allow {
		error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, *ownerappkey, qkms_common.QKMS_BEHAVIOR_WRITE)
		if err != nil {
			glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, "no valid kar"))
			return &qkms_proto.UpdateAccessKeyReply{ErrorCode: error_code}, err
		}
	}
	_, err = server.UpdateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, plain_cache_ak.OwnerAppkey, req.Version)
	if err != nil {
		glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Update AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_AK_SUCCESS}, nil
}

func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *qkms_proto.RotateAccessKeyRequest) (*qkms_proto.RotateAccessKeyReply, error) {
	return nil, nil
}

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
	}
	glog.Info(fmt.Sprintf("Get AK Index Success, AK indexs :%+v,client appkey:%s", reply_aks, *ownerappkey))
	return reply, nil
}
