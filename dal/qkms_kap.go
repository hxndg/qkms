package qkms_dal

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_model "qkms/model"

	"github.com/golang/glog"

	"gorm.io/gorm"
)

// UserAppkey    string `gorm:"index:idx_kar;column:userappkey"`
// NameSpace     string `gorm:"index:idx_kar;column:namespace"`
// KeyName       string `gorm:"index:idx_kar;column:keyname"`
// Environment   string `gorm:"index:idx_kar;column:environment"`
// OperationType string `gorm:"index:idx_kar;column:operationtype"`
// Effect        string `gorm:"column:effect"`

func (d *Dal) CreateOrUpdateKeyAuthorizationPolicy(ctx context.Context, namespace string, name string, environment string, userappkey string, action string, effect string) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		new_kap := qkms_model.KeyAuthorizationPolicy{
			NameSpace:     namespace,
			KeyName:       name,
			Environment:   environment,
			UserAppkey:    userappkey,
			OperationType: action,
			Effect:        effect,
		}

		if tx.Model(&qkms_model.KeyAuthorizationPolicy{}).Where("namespace = ? AND keyname = ? AND environment = ? AND userappkey = ? And operationtype = ?", namespace, name, environment, userappkey, action).Updates(&new_kap).RowsAffected == 0 {
			tx.Model(&qkms_model.KeyAuthorizationPolicy{}).Create(&new_kap)
		}

		glog.Info(fmt.Sprintf("CreateOrUpdate KAR success!, KAR Info :%+v", new_kap))

		return nil
	})
	if trans_error != nil {
		return qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_FAILED, trans_error
	}
	return qkms_common.QKMS_ERROR_CODE_CHANGE_KAP_SUCCESS, nil
}

func (d *Dal) CheckKeyAuthorizationPolicy(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (*qkms_model.KeyAuthorizationPolicy, error) {
	var kar qkms_model.KeyAuthorizationPolicy
	result := d.Query(ctx).Where("namespace = ? AND name = ? AND environment = ? AND ownerappkey = ? AND grantedappkey = ? And behavior = ?", namespace, name, environment, ownerappkey, grantedappkey, behavior).First(&kar)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("namespace:%s, name: %s,environment:%s,ownerappkey:%s,grantedappkey:%s,behavior:%s, error :%s", namespace, name, environment, ownerappkey, grantedappkey, behavior, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire KAR success!, KAR Info :%+v", kar))
	return &kar, nil
}

func (d *Dal) AccquireAllKAR(ctx context.Context) (*[]qkms_model.KeyAuthorizationPolicy, error) {
	var kars []qkms_model.KeyAuthorizationPolicy
	_ = d.Query(ctx).Find(&kars)

	return &kars, nil
}
