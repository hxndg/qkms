package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) CreateKeyEncryptionKey(ctx context.Context, req *qkms_proto.CreateKeyEncryptionKeyRequest) (*qkms_proto.CreateKeyEncryptionKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	_, err = server.CreateKEKInternal(ctx, req.NameSpace, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Create KEK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create KEK success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_SUCCESS}, nil
}
