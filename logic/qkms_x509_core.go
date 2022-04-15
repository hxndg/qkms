package qkms_logic

import (
	"context"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) GenerateCredentialInternal(ctx context.Context, organization string, country string, province string, locality string, name string, key_type string) (*PlainCacheUser, error) {

	appkey := qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(40))
	commonname := fmt.Sprintf("user=%s,appkey=%s,version=0", name, appkey)
	cert, key, err := server.GenerateCert(ctx, organization, country, province, locality, commonname, key_type)
	if err != nil {
		return nil, err
	}
	/* user only exist single namespace :user, single environment: production*/
	_, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, "user", "production")
	if err != nil {
		glog.Error("Create User failed, no related kek for database. Request for namespace:user, environment: production")
		return nil, err
	}
	kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:user, environment: production, kek: %+v", *plain_cache_kek))
		return nil, err
	}
	plain_cache_user := &PlainCacheUser{
		Name:         name,
		AppKey:       appkey,
		Cert:         *cert,
		KeyPlaintext: qkms_crypto.Base64Encoding([]byte(*key)),
		KeyType:      key_type,
		Version:      0,
		KEKVersion:   plain_cache_kek.Version,
	}
	model_user, err := PlainCacheUser2ModelUser(plain_cache_user, kek_plaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create user failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v, err:%s", *model_user, *plain_cache_kek, err.Error()))
		return nil, err
	}
	_, err = qkms_dal.GetDal().CreateUser(ctx, model_user)
	if err != nil {
		glog.Error(fmt.Sprintf("Create user failed, insert into database filed, encrypted_ak:%+v, err:%s", model_user, err.Error()))
		return nil, err
	}

	return plain_cache_user, nil
}

func (server *QkmsRealServer) UpdateCredentialInternal(ctx context.Context, organization string, country string, province string, locality string, name string, appkey string, key_type string, version uint64) (*PlainCacheUser, error) {

	commonname := fmt.Sprintf("user=%s,appkey=%s,version=%d", name, appkey, version)
	cert, key, err := server.GenerateCert(ctx, organization, country, province, locality, commonname, key_type)
	if err != nil {
		return nil, err
	}
	/* user only exist single namespace :user, single environment: production*/
	_, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, "user", "production")
	if err != nil {
		glog.Error("Create User failed, no related kek for database. Request for namespace:user, environment: production")
		return nil, err
	}
	kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:user, environment: production, kek: %+v", *plain_cache_kek))
		return nil, err
	}
	plain_cache_user := &PlainCacheUser{
		Name:         name,
		AppKey:       appkey,
		Cert:         *cert,
		KeyPlaintext: qkms_crypto.Base64Encoding([]byte(*key)),
		KeyType:      key_type,
		Version:      version,
		KEKVersion:   plain_cache_kek.Version,
	}
	model_user, err := PlainCacheUser2ModelUser(plain_cache_user, kek_plaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create user failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v, err:%s", *model_user, *plain_cache_kek, err.Error()))
		return nil, err
	}
	_, err = qkms_dal.GetDal().UpdateUser(ctx, model_user)
	if err != nil {
		glog.Error(fmt.Sprintf("Create user failed, insert into database filed, encrypted_ak:%+v, err:%s", model_user, err.Error()))
		return nil, err
	}

	return plain_cache_user, nil
}
