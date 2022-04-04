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

func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *qkms_proto.GrantAccessKeyAuthorizationRequest) (*qkms_proto.GrantAccessKeyAuthorizationReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Grant KAR failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to grant KAR, Client cert subject :%+v", subject))
		}
	}
	plain_cache_ak, err := server.ReadAKInternal(ctx, req.NameSpace, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_INVALID}, err
	}
	if plain_cache_ak.OwnerAppkey != *ownerappkey {
		glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, "requester is not key owner"))
	}
	erro_code, err := server.GrantKARInternal(ctx, req.NameSpace, req.Name, req.Environment, plain_cache_ak.OwnerAppkey, req.Appkey, req.Behavior)
	if err != nil {
		glog.Info(fmt.Sprintf("Grant KAR failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: erro_code}, err
	}
	glog.Info(fmt.Sprintf("Grant KAR success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.GrantAccessKeyAuthorizationReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_KAR_GRANTED}, nil
}
