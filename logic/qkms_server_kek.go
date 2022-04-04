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

func (server *QkmsRealServer) CreateKeyEncryptionKey(ctx context.Context, req *qkms_proto.CreateKeyEncryptionKeyRequest) (*qkms_proto.CreateKeyEncryptionKeyReply, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Create KEK failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_INVALID_CREDENTIALS}, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to create KEK, Client cert subject :%+v", subject))
		}
	}
	_, err := server.CreateKEKInternal(ctx, req.NameSpace, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Create KEK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create KEK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_SUCCESS}, nil
}
