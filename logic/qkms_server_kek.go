package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

// todo fix to create
func (server *QkmsRealServer) CreateKeyEncryptionKey(ctx context.Context, req *qkms_proto.CreateKeyEncryptionKeyRequest) (*qkms_proto.CreateKeyEncryptionKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		glog.Info(fmt.Sprintf("CreateKeyEncryptionKey failed, req:%+v, ower app key %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	plain_cache_kek, err := server.CreateKEKInternal(ctx, req.Name, req.Environment, req.KeyType, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create KEK failed, req:%+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create KEK Success, info %+v", *plain_cache_kek))
	return &qkms_proto.CreateKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_KEK_SUCCESS}, nil
}
