package qkms_dal

import (
	"context"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_model "qkms/model"

	"github.com/golang/glog"

	"gorm.io/gorm"
)

func (d *Dal) AccquireKeyEncryptionKey(ctx context.Context, namespace string, environment string) (*qkms_model.KeyEncryptionKey, error) {
	var kek qkms_model.KeyEncryptionKey
	result := d.Query(ctx).Where("namespace = ? AND environment = ?", namespace, environment).First(&kek)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire KEK failed!, Namespace: %s, Environment: %s, Failed Info: %s", namespace, environment, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire KEK success!, KEK Info :%+v", kek))
	return &kek, nil
}

func (d *Dal) CreateKeyEncryptionKey(ctx context.Context, key *qkms_model.KeyEncryptionKey) (int64, error) {
	result := d.Query(ctx).Create(key)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Create new KEK failed! KEK Info: %+v, Failed Info: %s", *key, result.Error.Error()))
		return 500, result.Error
	}
	glog.Info(fmt.Sprintf("Create new KEK success! KEK Info: %+v", *key))

	return 200, nil
}

func (d *Dal) UpdateKeyEncryptionKey(ctx context.Context, key *qkms_model.KeyEncryptionKey, plain_old_kek string, plain_new_kek string) (int64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 先读取，如果找不到就放弃了,借此尽量用读锁，放弃写锁的争用
		var old_kek qkms_model.KeyEncryptionKey
		if err := tx.Model(&qkms_model.KeyEncryptionKey{}).Where("namespace = ? AND keytype = ? AND environment = ? AND version = ? AND rkversion = ? AND ownerappkey = ?", key.NameSpace, key.KeyType, key.Environment, key.Version-1, key.RKVersion, key.OwnerAppkey).First(&old_kek).Error; err != nil {
			glog.Error(fmt.Sprintf("Update new KEK failed! Can't find original KEK: %+v, Failed Info: %s", *key, err.Error()))
			return err
		}
		if err := tx.Model(&old_kek).Updates(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Update new KEK failed! Can't update finded original KEK. KEK Info: %+v, Failed Info: %s", *key, err.Error()))
			return err
		}
		glog.Info(fmt.Sprintf("Try lock update new KEK success! KEK Info: %+v", *key))
		var aks []qkms_model.AccessKey
		// 先获取所有使用这个kek的ak
		if err := tx.Model(&qkms_model.AccessKey{}).Where("namespace = ? AND environment = ? AND kekversion = ?", key.NameSpace, key.Environment, key.Version-1).Find(&aks).Error; err != nil {
			glog.Error(fmt.Sprintf("Update new KEK to find related AKs failed: KEK Info: %+v, Failed Info: %s", *key, err.Error()))
			return err
		}

		for i := 0; i < len(aks); i++ {
			old_enc_content, err := qkms_crypto.Base64Decoding(aks[i].EncryptedAK)
			if err != nil {
				glog.Error(fmt.Sprintf("Update new KEK to decode base64 related AK failed! KEK Info:%+v, AK Info: %+v, Failed Info: %s", *key, aks[i], err.Error()))
				return err
			}

			plain_content, err := qkms_crypto.AesCBCDecrypt(old_enc_content, []byte(plain_old_kek))
			if err != nil {
				glog.Error(fmt.Sprintf("Update new KEK to decrypted related AK failed! KEK Info:%+v, AK Info: %+v, Failed Info: %s", *key, aks[i], err.Error()))
				return err
			}
			new_enc_content, err := qkms_crypto.AesCBCEncrypt(plain_content, []byte(plain_new_kek))
			if err != nil {
				glog.Error(fmt.Sprintf("Update new KEK to encrypt related AK failed! KEK Info:%+v, AK Info: %+v, Failed Info: %s", *key, aks[i], err.Error()))
				return err
			}
			base64_new_enc_content := qkms_crypto.Base64Encoding(new_enc_content)

			new_ak := aks[i]
			new_ak.EncryptedAK = base64_new_enc_content
			new_ak.KEKVersion = key.Version
			if err := tx.Model(&qkms_model.AccessKey{}).Where(aks[i]).Updates(new_ak).Error; err != nil {
				glog.Error(fmt.Sprintf("Update new KEK related new AK failed! KEK Info:%+v, AK Info: %+v, Failed Info: %s", *key, aks[i], err.Error()))
				return err
			}
			glog.Error(fmt.Sprintf("Update new KEK related AK success ! old AK : %+v, new AK : %+v", aks[i], new_ak))
		}

		glog.Info(fmt.Sprintf("Update new KEK success! KEK Info:%+v", *key))
		return nil
	})

	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}
