package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"
	"gorm.io/gorm"
)

func (d *Dal) AccquireNamespace(ctx context.Context, name string, environment string) (*qkms_model.NameSpace, error) {
	var namespace_info qkms_model.NameSpace
	result := d.Query(ctx).Where("name = ? AND environment = ?", name, environment).First(&namespace_info)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire Namespace failed!, Namespace: %s, Environment: %s, Failed Info: %s", name, environment, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire Namespace success!, Namespace Info :%+v", namespace_info))
	return &namespace_info, nil
}

func (d *Dal) UpdateNameSpace(ctx context.Context, name string, environment string, kek string, ownerappkey string) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容，先读取旧的ak
		new_namespace := &qkms_model.NameSpace{
			Name:        name,
			Environment: environment,
			OwnerAppkey: ownerappkey,
			KEK:         kek,
		}
		var old_namespace qkms_model.NameSpace
		if err := tx.Model(&qkms_model.AccessKey{}).Where("name = ? AND environment = ?", new_namespace.Name, environment).First(&old_namespace).Error; err != nil {
			glog.Error(fmt.Sprintf("Update NameSpace failed, Can't find original NameSpace! NameSpace Info :%+v, Failed info: %s", *new_namespace, err.Error()))
			return err
		}
		if err := tx.Model(&old_namespace).Updates(new_namespace).Error; err != nil {
			glog.Error(fmt.Sprintf("Update NameSpace failed, NameSpace Info :%+v, Failed info: %s", *new_namespace, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Update NameSpace success!, NameSpace Info :%+v", *new_namespace))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}
