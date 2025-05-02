package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) CreateNameSpace(ctx context.Context, req *qkms_proto.CreateNameSpaceRequest) (*qkms_proto.CreateNameSpaceReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.CreateNameSpaceReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_NAMESPACE_FAILED}, err
	}

	_, err = server.CreateNameSpaceInternal(ctx, req.Name, req.Environment, *ownerappkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Create NameSpace failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.CreateNameSpaceReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_NAMESPACE_FAILED}, err
	}
	glog.Info(fmt.Sprintf("Create NameSpace success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.CreateNameSpaceReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_CREATE_NAMESPACE_SUCCESS, ErrorMsg: "success"}, nil
}

func (server *QkmsRealServer) ReadNameSpace(ctx context.Context, req *qkms_proto.ReadNameSpaceRequest) (*qkms_proto.ReadNameSpaceReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.ReadNameSpaceReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_NAMESPACE_FAILED}, err
	}

	namespace_info, err := server.ReadNameSpaceInternal(ctx, req.Name, req.Environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Read NameSpace failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.ReadNameSpaceReply{
			ErrorCode:   qkms_common.QKMS_ERROR_CODE_READ_NAMESPACE_SUCCESS,
			ErrorMsg:    "success",
			Name:        namespace_info.Name,
			Environment: namespace_info.Environment,
			OwnerAppkey: namespace_info.OwnerAppkey,
			KEK:         namespace_info.KEK,
		}, err
	}
	glog.Info(fmt.Sprintf("Read NameSpace success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.ReadNameSpaceReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_READ_NAMESPACE_SUCCESS}, nil
}

func (server *QkmsRealServer) UpdateNameSpace(ctx context.Context, req *qkms_proto.UpdateNameSpaceInfoRequest) (*qkms_proto.UpdateNameSpaceInfoReply, error) {
	ownerappkey, err := LoadAppKey(ctx)
	if err != nil {
		return &qkms_proto.UpdateNameSpaceInfoReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_NAMESPACE_FAILED}, err
	}

	err = server.UpdateNameSpaceInfoInternal(ctx, req.Name, req.Environment, req.KEK, req.OwnerAppkey)
	if err != nil {
		glog.Info(fmt.Sprintf("Read NameSpace failed, req:%+v, ownerappkey: %s, error: %s", req.String(), *ownerappkey, err.Error()))
		return &qkms_proto.UpdateNameSpaceInfoReply{
			ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_NAMESPACE_FAILED,
		}, err
	}
	glog.Info(fmt.Sprintf("Read NameSpace success, req:%+v, ownerappkey: %s", req.String(), *ownerappkey))
	return &qkms_proto.UpdateNameSpaceInfoReply{ErrorCode: qkms_common.QKMS_ERROR_CODE_UPDATE_NAMESPACE_SUCCESS}, nil
}
