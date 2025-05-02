package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"
)

func (d *Dal) GetRoles(ctx context.Context) (*[]qkms_model.Role, error) {
	var roles []qkms_model.Role
	_ = d.Query(ctx).Find(&roles)
	return &roles, nil
}

func (d *Dal) CreateRole(ctx context.Context, role *qkms_model.Role) (uint64, error) {
	result := d.Query(ctx).Create(role)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Create new role failed! role Info: %+v, Failed Info: %s", *role, result.Error.Error()))
		return 500, result.Error
	}
	glog.Info(fmt.Sprintf("Create new role success! KEK Info: %+v", *role))

	return 200, nil
}
