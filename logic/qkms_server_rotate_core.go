package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	"time"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) RotateNameSpaceKeyEncryptionKeyInternal(namespace string, environment string) error {
	_, old_kek_info, err := server.ReadKEKByNamespace(context.Background(), namespace, environment)
	if err != nil {
		glog.Info(fmt.Sprintf("Read NameSpace KEK failed, namespace %s, environment %s, error: %s", namespace, environment, err.Error()))
		return err
	}

	currentTime := time.Now().Unix()
	kek_name := fmt.Sprintf("%s-%s-%s-%d", namespace, environment, "kek", currentTime)
	_, err = server.CreateKEKInternal(context.Background(), kek_name, environment, old_kek_info.KeyType, old_kek_info.OwnerAppkey)
	if err != nil {
		glog.Info(fmt.Sprintf("RotateKEKE failed, Create KEK failed, kek name %s, prev version kek info:%+v, error: %s", kek_name, *old_kek_info, err.Error()))
		return err
	}
	_, err = qkms_dal.GetDal().UpdateNameSpace(context.Background(), namespace, environment, kek_name, old_kek_info.OwnerAppkey)
	if err != nil {
		glog.Info(fmt.Sprintf("RotateKEKE failed, Update Namespace failed, kek name: %s, prev version kek info:%+v, , error: %s", kek_name, *old_kek_info, err.Error()))
		return err
	}
	glog.Info(fmt.Sprintf("Rotate NameSpaceKEK success, prev version kek info:%+v, namespace: %s, environment %s", *old_kek_info, namespace, environment))
	return nil
}

func (server *QkmsRealServer) RotateAccessKeyInternal(namespace string, name string, key_type string, environment string) error {

	old_plain_cache_ak, err := server.ReadAKInternal(context.Background(), namespace, name, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("RotateAccessKeyInternal AK failed, can't get old ak from database. Request for namespace:%s name:%s, environment:%s", namespace, name, environment))
		return err
	}

	if key_type != old_plain_cache_ak.KeyType {
		glog.Warning(fmt.Sprintf("RotateAccessKeyInternal AK Warning, key type not match. new key type %s, old key %+v", key_type, *old_plain_cache_ak))
	}
	_, plain_cache_kek, err := server.ReadKEKByNamespace(context.Background(), namespace, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("RotateAccessKeyInternal AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", namespace, name, environment))
		return err
	}
	kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", namespace, name, environment, *plain_cache_kek))
		return err
	}
	plain_cache_ak := &PlainCacheAK{
		NameSpace:      old_plain_cache_ak.NameSpace,
		Name:           old_plain_cache_ak.Name,
		KeyType:        key_type,
		Environment:    environment,
		Version:        old_plain_cache_ak.Version + 1,
		LifeTime:       old_plain_cache_ak.LifeTime,
		RotateDuration: old_plain_cache_ak.RotateDuration,
		KEK:            plain_cache_kek.Name,
		OwnerAppkey:    old_plain_cache_ak.OwnerAppkey,
		Attributes:     old_plain_cache_ak.Attributes,
	}

	if check, ok := server.cipher_key_len_map.Get(key_type); ok {
		cipher_key_len := check.(int)
		plain_cache_ak.AKPlaintext = qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(int(cipher_key_len)))
	} else {
		return errors.New("key Type Not supportked")
	}

	model_ak, err := PlainCacheAK2ModelAK(plain_cache_ak, kek_plaintext)

	if err != nil {
		glog.Error(fmt.Sprintf("Rotate AK failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v", *model_ak, *plain_cache_kek))
		return err
	}
	_, err = qkms_dal.GetDal().UpdateAccessKey(context.Background(), model_ak)
	if err != nil {
		glog.Error(fmt.Sprintf("Rotate AK failed, insert into database filed, encrypted_ak:%+v", model_ak))
		return err
	}

	server.ak_map.Remove(namespace + "#" + name + "#" + environment)

	return nil
}
