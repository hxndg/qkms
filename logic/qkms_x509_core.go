package qkms_logic

import (
	"context"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) GenerateCredentialOnly(ctx context.Context, organization string, country string, province string, locality string, name string, key_type string, version uint64, kek string) (*PlainCacheUser, error) {

	appkey := qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(32))
	commonname := fmt.Sprintf("user:%s,appkey:%s", name, appkey)
	/* pem format key & cert, no need to base64 encoding */
	cert, key, err := server.GenerateCert(ctx, organization, country, province, locality, commonname, key_type)
	if err != nil {
		return nil, err
	}

	plain_cache_user := &PlainCacheUser{
		Name:         name,
		AppKey:       appkey,
		Cert:         *cert,
		KeyPlaintext: *key,
		KeyType:      key_type,
		Version:      version,
		KEK:          kek,
	}

	return plain_cache_user, nil
}

func (server *QkmsRealServer) InsertCacheUser2DB(ctx context.Context, plain_cache_user *PlainCacheUser) (*PlainCacheUser, error) {

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

func (server *QkmsRealServer) GenerateCredentialAndInsertDB(ctx context.Context, organization string, country string, province string, locality string, name string, key_type string) (*PlainCacheUser, error) {

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
	plain_cache_user, err := server.GenerateCredentialOnly(ctx, organization, country, province, locality, name, key_type, 0, plain_cache_kek.Name)
	if err != nil {
		glog.Error("Create User failed, failed to create user. Request for namespace:user, environment: production")
		return nil, err
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

func (server *QkmsRealServer) RevokeCredentialInternal(ctx context.Context, appkey string) (*qkms_model.User, error) {
	user, err := qkms_dal.GetDal().RemoveUser(ctx, appkey)
	if err != nil {
		glog.Error("Remove user from database failed, err:%s", err.Error())
		return nil, err
	}
	err = server.RevokeCert(ctx, user.Cert)
	if err != nil {
		glog.Error("Remove user credential when revoke cert, err:%s", err.Error())
		return nil, err
	}
	return user, nil
}
