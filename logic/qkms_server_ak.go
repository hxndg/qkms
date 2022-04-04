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

func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *qkms_proto.ReadAccessKeyRequest) (*qkms_proto.ReadAccessKeyReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Read AK failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to read accesskey, Client cert subject :%+v", subject))
		}
	}
	// return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("no auth info")

	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, *ownerappkey, qkms_common.QKMS_BEHAVIOR_READ)
	if err != nil {
		glog.Info(fmt.Sprintf("Read AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadAccessKeyReply{ErrorCode: error_code}, err
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
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Create AK failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to create new accesskey, Client cert subject :%+v", subject))
		}
	}

	_, err := server.CreateAKInternal(ctx, req.NameSpace, req.Name, req.AKPlaintext, req.KeyType, req.Environment, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create AK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.CreateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_AK_SUCCESS}, nil
}

func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *qkms_proto.UpdateAccessKeyRequest) (*qkms_proto.UpdateAccessKeyReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Update AK failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.UpdateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to update AK, Client cert subject :%+v", subject))
		}
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
	error_code, err := server.CheckKAR(ctx, plain_cache_ak.NameSpace, plain_cache_ak.Name, plain_cache_ak.Environment, plain_cache_ak.OwnerAppkey, *ownerappkey, qkms_common.QKMS_BEHAVIOR_WRITE)
	if err != nil {
		glog.Info(fmt.Sprintf("Update AK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, "no valid kar"))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: error_code}, err
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
