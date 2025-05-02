package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"

	"gorm.io/gorm"
)

func (d *Dal) AccquireKeyEncryptionKey(ctx context.Context, name string, environment string) (*qkms_model.KeyEncryptionKey, error) {
	var kek qkms_model.KeyEncryptionKey
	result := d.Query(ctx).Where("name = ? AND environment = ?", name, environment).First(&kek)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire KEK failed!, Name: %s, Environment: %s, Failed Info: %s", name, environment, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire KEK success!, KEK Info :%+v", kek))
	return &kek, nil
}

func (d *Dal) CreateKeyEncryptionKey(ctx context.Context, key *qkms_model.KeyEncryptionKey) (uint64, error) {
	result := d.Query(ctx).Create(key)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Create new KEK failed! KEK Info: %+v, Failed Info: %s", *key, result.Error.Error()))
		return 500, result.Error
	}
	glog.Info(fmt.Sprintf("Create new KEK success! KEK Info: %+v", *key))

	return 200, nil
}

func (d *Dal) CreateNameSpaceAndKeyEncryptionKey(ctx context.Context, namespace string, environment string, key *qkms_model.KeyEncryptionKey) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 先把KEK写入到数据库，然后写Namepsace
		if err := tx.Create(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Create new KEK failed! KEK Info: %+v, Failed Info: %s", *key, err.Error()))
			return err
		}
		new_namespace := qkms_model.NameSpace{
			Name:        namespace,
			KEK:         key.Name,
			Environment: key.Environment,
			OwnerAppkey: key.OwnerAppkey,
		}
		if err := tx.Create(&new_namespace).Error; err != nil {
			glog.Error(fmt.Sprintf("Create new Namespace failed! Namespace Info: %+v, Failed Info: %s", new_namespace, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Create KEK and namespace success! KEK Info:%+v, Namespace Info:%+v", *key, new_namespace))
		return nil
	})

	if trans_error != nil {
		return 500, trans_error
	}

	return 200, nil
}
