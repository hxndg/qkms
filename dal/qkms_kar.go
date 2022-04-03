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
			glog.Error(fmt.Sprintf("Create KAR failed!, KAR Info :%+v, Failed info: %s", *kar, err.Error()))
			return err
		}
		glog.Info(fmt.Sprintf("Create KAR success!, AK Info :%+v", *kar))
		return nil
	})
	if trans_error != nil {
		return qkms_common.QKMS_ERROR_CODE_CREATE_KAR_FAILED, trans_error
	}
	return qkms_common.QKMS_ERROR_CODE_CREATE_KAR_SUCCESS, nil
}

func (d *Dal) CheckKeyAuthorizationRelation(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (*qkms_model.KeyAuthorizationRelation, error) {
	var kar qkms_model.KeyAuthorizationRelation
	result := d.Query(ctx).Where("namespace = ? AND name = ? AND environment = ? AND ownerappkey = ? AND grantedappkey = ? And behavior = ?", namespace, name, environment, ownerappkey, grantedappkey, behavior).First(&kar)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("namespace:%s, name: %s,environment:%s,ownerappkey:%s,grantedappkey:%s,behavior:%s, error :%s", namespace, name, environment, ownerappkey, grantedappkey, behavior, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire KAR success!, KAR Info :%+v", kar))
	return &kar, nil
}
