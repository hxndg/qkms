package qkms_dal

import (
	"context"
	"fmt"
	qkms_model "qkms/model"

	"github.com/golang/glog"
	"gorm.io/gorm"
)

func (d *Dal) CreateRevokeCert(ctx context.Context, cert *qkms_model.RevokeCert) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(cert).Error; err != nil {
			glog.Error(fmt.Sprintf("Create revoke cert failed!, user Info :%+v, Failed info: %s", *cert, err.Error()))
			return err
		}

		// 返回 nil 提交事务
		glog.Info(fmt.Sprintf("Create revoke cert success!, AK Info :%+v", *cert))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) AccquireRevokeCert(ctx context.Context, appkey string) (*qkms_model.RevokeCert, error) {
	var cert qkms_model.RevokeCert
	result := d.Query(ctx).Where("appkey = ?", appkey).First(&cert)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire revoke cert failed!, appkey %s, Failed Info: %s", appkey, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire revoke cert success!, AK Info :%+v", cert))
	return &cert, nil
}

func (d *Dal) AccquireRevokeCerts(ctx context.Context) (*[]qkms_model.RevokeCert, error) {
	var certs []qkms_model.RevokeCert
	result := d.Query(ctx).Find(&certs)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire revoke certs failed!, Failed Info: %s", result.Error.Error()))
		return nil, result.Error
	}
	glog.Info("Accquire revoke certs success!")
	return &certs, nil
}

func (d *Dal) RemoveRevokeCert(ctx context.Context, appkey string) error {
	var cert qkms_model.RevokeCert
	result := d.Query(ctx).Where("appkey = ?", appkey).First(&cert)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Remove revoke cert failed!, appkey %s, Failed Info: %s", appkey, result.Error.Error()))
		return result.Error
	}

	glog.Info(fmt.Sprintf("Plan to remove revoke cert !, cert Info :%+v", cert))
	result = d.Query(ctx).Where("appkey = ?", appkey).Delete(&cert)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Remove revoke cert failed!, appkey %s, Failed Info: %s", appkey, result.Error.Error()))
		return result.Error
	}
	glog.Info("Remove revoke cert success!")
	return nil
}
