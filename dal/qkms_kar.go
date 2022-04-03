package qkms_dal

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_model "qkms/model"

	"github.com/golang/glog"

	"gorm.io/gorm"
)

func (d *Dal) CreateKeyAuthorizationRelation(ctx context.Context, kar *qkms_model.KeyAuthorizationRelation) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(kar).Error; err != nil {
			glog.Error(fmt.Sprintf("Create KAR failed!, AK Info :%+v, Failed info: %s", *kar, err.Error()))
			return err
		}

		// 返回 nil 提交事务
		glog.Info(fmt.Sprintf("Create KAR success!, AK Info :%+v", *kar))
		return nil
	})
	if trans_error != nil {
		return qkms_common.QKMS_ERROR_CODE_CREATE_KAR_FAILED, trans_error
	}
	return qkms_common.QKMS_ERROR_CODE_CREATE_KAR_SUCCESS, nil
}

func (d *Dal) CheckKeyAuthorizationRelation(ctx context.Context, kar *qkms_model.KeyAuthorizationRelation) (uint64, error) {
	var ak qkms_model.AccessKey
	result := d.Query(ctx).Where("namespace = ? AND name = ? AND environment = ? AND ownerappkey = ? AND grantedappkey = ? And behavior = ?", kar.NameSpace, kar.Name, kar.Environment, kar.OwnerAppkey, kar.GrantedAppkey, kar.Behavior).First(&ak)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Check KAR failed!, KAR: %+v, Failed Info: %s", *kar, result.Error.Error()))
		return qkms_common.QKMS_ERROR_CODE_KAR_NOT_FIND, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire KAR success!, KAR Info :%+v", ak))
	return qkms_common.QKMS_ERROR_CODE_KAR_FIND, nil
}
