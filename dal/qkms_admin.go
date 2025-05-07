package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"
)

func (d *Dal) GetAdmin(ctx context.Context) (*[]qkms_model.Administrator, error) {
	var admins []qkms_model.Administrator
	_ = d.Query(ctx).Find(&admins)
	return &admins, nil
}

func (d *Dal) GrantAdmin(ctx context.Context, appkey string) (uint64, error) {
	admin := qkms_model.Administrator{
		AppKey: appkey,
	}

	result := d.Query(ctx).Create(&admin)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Create new adming failed! role Info: %+v, Failed Info: %s", admin, result.Error.Error()))
		return 500, result.Error
	}
	glog.Info(fmt.Sprintf("Create new admin success! KEK Info: %+v", admin))

	return 200, nil
}

func (d *Dal) RemoveAdmin(ctx context.Context, appkey string) (uint64, error) {

	result := d.Query(ctx).Where("appkey = ?", appkey).Delete(&qkms_model.Administrator{})

	if result.Error != nil {
		glog.Error(fmt.Sprintf("Create new adming failed! appkey: %+v, Failed Info: %s", appkey, result.Error.Error()))
		return 500, result.Error
	}
	glog.Info(fmt.Sprintf("remove admin success! appkey: %+v", appkey))

	return 200, nil
}
