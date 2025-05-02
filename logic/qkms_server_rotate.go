package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) RotateNameSpaceKeyEncryptionKey(ctx context.Context, req *qkms_proto.RotateNameSpaceKeyEncryptionKeyRequest) (*qkms_proto.RotateNameSpaceKeyEncryptionKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.RotateNameSpaceKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_NAMESPACE_KEK_FAILED}, err
	}
	err = server.RotateNameSpaceKeyEncryptionKeyInternal(req.NameSpace, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Rotate NameSpace KEK failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.RotateNameSpaceKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_NAMESPACE_KEK_FAILED}, err
	}
	return &qkms_proto.RotateNameSpaceKeyEncryptionKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_NAMESPACE_KEK_SUCCESS}, nil
}

func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *qkms_proto.RotateAccessKeyRequest) (*qkms_proto.RotateAccessKeyReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		glog.Info(fmt.Sprintf("Rotate AccessKey failed, req:%+v, ower app key %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.RotateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_ACCESS_KEY_FAILED}, err
	}
	err = server.RotateAccessKeyInternal(req.NameSpace, req.Name, req.KeyType, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Rotate Access Key failed, req:%+v, error: %s", req.String(), err.Error()))
		return &qkms_proto.RotateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_ACCESS_KEY_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Rotate Access Key success, req:%+v", req.String()))
	return &qkms_proto.RotateAccessKeyReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_ROTATE_ACCESS_KEY_SUCCESS}, nil
}
