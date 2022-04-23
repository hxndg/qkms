package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"
	"gorm.io/gorm"
)

func (d *Dal) CreateUser(ctx context.Context, user *qkms_model.User) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		var kek qkms_model.KeyEncryptionKey
		if err := tx.Model(&qkms_model.KeyEncryptionKey{}).Where("namespace = ? AND environment = ? AND version = ? ", "user", "production", user.KEKVersion).First(&kek).Error; err != nil {
			glog.Error(fmt.Sprintf("Create new user failed! Can't find original KEK Info: %+v, Failed Info: %s", *user, err.Error()))
			return err
		}
		// 现在尝试写入ak的内容
		if err := tx.Create(user).Error; err != nil {
			glog.Error(fmt.Sprintf("Create user failed!, user Info :%+v, Failed info: %s", *user, err.Error()))
			return err
		}

		// 返回 nil 提交事务
		glog.Info(fmt.Sprintf("Create user success!, AK Info :%+v", *user))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) UpdateUser(ctx context.Context, user *qkms_model.User) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		var kek qkms_model.KeyEncryptionKey
		if err := tx.Model(&qkms_model.KeyEncryptionKey{}).Where("namespace = user AND environment = production AND version = ? ", user.KEKVersion).First(&kek).Error; err != nil {
			glog.Error(fmt.Sprintf("Create new user failed! Can't find original KEK Info: %+v, Failed Info: %s", *user, err.Error()))
			return err
		}
		var old_user qkms_model.User
		if err := tx.Model(&qkms_model.User{}).Where("name = ? AND appkey = ? AND keytype = ? AND version = ? AND kekversion = ?", user.Name, user.AppKey, user.KeyType, user.Version-1, user.KEKVersion).First(&old_user).Error; err != nil {
			glog.Error(fmt.Sprintf("Update User failed, Can't find original User! User Info :%+v, Failed info: %s", *user, err.Error()))
			return err
		}
		if err := tx.Model(&old_user).Updates(user).Error; err != nil {
			glog.Error(fmt.Sprintf("Update User failed, User Info :%+v, Failed info: %s", *user, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Update User success!, AK Info :%+v", *user))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) AccquireUser(ctx context.Context, appkey string) (*qkms_model.User, error) {
	var user qkms_model.User
	result := d.Query(ctx).Where("appkey = ?", appkey).First(&user)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire User failed!, appkey %s, Failed Info: %s", appkey, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire User success!, AK Info :%+v", user))
	return &user, nil
}
