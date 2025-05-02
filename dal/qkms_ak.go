package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"

	"gorm.io/gorm"
)

func (d *Dal) CreateAccessKey(ctx context.Context, key *qkms_model.AccessKey) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容
		if err := tx.Create(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Create AK failed!, AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}

		// 返回 nil 提交事务
		glog.Info(fmt.Sprintf("Create AK success!, AK Info :%+v", *key))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) UpdateAccessKey(ctx context.Context, key *qkms_model.AccessKey) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容，先读取旧的ak
		var old_ak qkms_model.AccessKey
		if err := tx.Model(&qkms_model.AccessKey{}).Where("namespace = ? AND name = ? AND keytype = ? AND environment = ? AND version = ? AND ownerappkey = ?", key.NameSpace, key.Name, key.KeyType, key.Environment, key.Version-1, key.OwnerAppkey).First(&old_ak).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, Can't find original AK! AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}
		if err := tx.Model(&old_ak).Updates(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Update AK success!, AK Info :%+v", *key))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) AccquireAccessKey(ctx context.Context, namespace string, name string, environment string) (*qkms_model.AccessKey, error) {
	var ak qkms_model.AccessKey
	result := d.Query(ctx).Where("namespace = ? AND name = ? AND environment = ?", namespace, name, environment).First(&ak)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire AK failed!, Namespace: %s, Name: %s, Environment: %s, Failed Info: %s", namespace, name, environment, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire AK success!, AK Info :%+v", ak))
	return &ak, nil
}

func (d *Dal) GetAccessKeyIndex(ctx context.Context, namespace string) (*[]qkms_model.AccessKey, error) {
	var aks []qkms_model.AccessKey
	if len(namespace) != 0 {
		_ = d.Query(ctx).Where("namespace = ?", namespace).Find(&aks)
	} else {
		_ = d.Query(ctx).Find(&aks)
	}
	return &aks, nil
}

func (d *Dal) GetAutoRotateAccessKeys(ctx context.Context) (*[]qkms_model.AccessKey, error) {
	var aks []qkms_model.AccessKey
	_ = d.Query(ctx).Not("rotateduration = ?", 0).Find(&aks)

	return &aks, nil
}
