package qkms_logic

import (
	"context"
	"fmt"
	qkms_dal "qkms/dal"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) GrantAdminInternal(ctx context.Context, appkey string) error {
	_, err := qkms_dal.GetDal().GrantAdmin(ctx, appkey)
	if err != nil {
		glog.Error(fmt.Sprintf("GrantAdminInternal failed, error: %s", err.Error()))
		return err
	}

	glog.Info(fmt.Sprintf("GrantAdminInternal success, appkey: %s", appkey))
	return nil
}

func (server *QkmsRealServer) IsAdmin(ctx context.Context, appkey string) (bool, error) {
	admins, err := qkms_dal.GetDal().GetAdmin(ctx)
	if err != nil {
		glog.Error(fmt.Sprintf("GetAdmin failed, error: %s", err.Error()))
		return false, err
	}
	for _, admin := range *admins {
		if admin.AppKey == appkey {
			glog.Info(fmt.Sprintf("Admin matched %s", appkey))
			return true, nil
		}
	}
	glog.Info(fmt.Sprintf("Admin mismatched, appkey: %s", appkey))

	return false, nil
}

func (server *QkmsRealServer) GetAdminsInternal(ctx context.Context) (*[]string, error) {
	admins, err := qkms_dal.GetDal().GetAdmin(ctx)
	if err != nil {
		glog.Error(fmt.Sprintf("GetAdmin failed, error: %s", err.Error()))
		return nil, err
	}
	var adminList []string
	for _, admin := range *admins {
		adminList = append(adminList, admin.AppKey)
	}
	glog.Info(fmt.Sprintf("GetAdminsInternal success, admins: %+v", adminList))
	return &adminList, nil
}
