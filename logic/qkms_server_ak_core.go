package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) ReadAKInternal(ctx context.Context, namespace string, name string, environment string) (*PlainCacheAK, error) {
	cmap_key := namespace + "#" + name + "#" + environment
	var cipher_cache_ak *CipherCacheAK
	if check, ok := server.ak_map.Get(cmap_key); ok {
		cipher_cache_ak = check.(*CipherCacheAK)
	} else {
		encrypted_ak, err := qkms_dal.GetDal().AccquireAccessKey(ctx, namespace, name, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get AK from database, request for namespace:%s name:%s, environment:%s", namespace, name, environment))
			return nil, err
		}
		_, plain_cache_kek, err := server.ReadKEKByName(ctx, encrypted_ak.KEK, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get related KEK for encrypted Ak, encrypted AK %+v", encrypted_ak))
			return nil, err
		}
		kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't Decoding plain kek %+v, ", *plain_cache_kek))
			return nil, err
		}
		cipher_cache_ak, err = ModelAK2CipherCacheAK(encrypted_ak, kek_plaintext, server.cache_key)
		if err != nil {
			return nil, err
		}
		server.ak_map.Set(cmap_key, cipher_cache_ak)
	}
	plain_cache_ak, err := CipherCacheAK2PlainCacheAK(cipher_cache_ak, server.cache_key)
	if err != nil {
		return nil, err
	}
	return plain_cache_ak, nil
}

func (server *QkmsRealServer) CreateAKInternal(ctx context.Context, namespace string, name string, ak_plaintext string, key_type string, environment string, owner_appkey string) (*PlainCacheAK, error) {

	cmap_key := namespace + "#" + name + "#" + environment
	// 先检索内存当中有没有缓存AK，如果有了就直接报错返回
	if _, ok := server.ak_map.Get(cmap_key); ok {
		return nil, errors.New("AK already exist")
	} else {
		_, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, namespace, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", namespace, name, environment))
			return nil, err
		}
		kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", namespace, name, environment, *plain_cache_kek))
			return nil, err
		}
		plain_cache_ak := &PlainCacheAK{
			NameSpace:   namespace,
			Name:        name,
			AKPlaintext: ak_plaintext,
			KeyType:     key_type,
			Environment: environment,
			Version:     0,
			KEK:         plain_cache_kek.Name,
			OwnerAppkey: owner_appkey,
		}
		model_ak, err := PlainCacheAK2ModelAK(plain_cache_ak, kek_plaintext)

		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v", *model_ak, *plain_cache_kek))
			return nil, err
		}
		_, err = qkms_dal.GetDal().CreateAccessKey(ctx, model_ak)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, insert into database filed, encrypted_ak:%+v", model_ak))
			return nil, err
		}
		cipher_cache_ak, err := PlainCacheAK2CipherCacheAK(plain_cache_ak, server.cache_key)
		if err != nil {
			glog.Error("Create encrypted success but cache failed")
		}
		server.ak_map.Set(cmap_key, cipher_cache_ak)

		return plain_cache_ak, nil
	}
}

func (server *QkmsRealServer) GenerateAKInternal(ctx context.Context, namespace string, name string, key_type string, environment string, owner_appkey string, lifetime uint64, rotate_duration uint64) (*PlainCacheAK, error) {

	cmap_key := namespace + "#" + name + "#" + environment
	// 先检索内存当中有没有缓存AK，如果有了就直接报错返回
	if _, ok := server.ak_map.Get(cmap_key); ok {
		return nil, errors.New("AK already exist")
	} else {
		_, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, namespace, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", namespace, name, environment))
			return nil, err
		}
		kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", namespace, name, environment, *plain_cache_kek))
			return nil, err
		}
		plain_cache_ak := &PlainCacheAK{
			NameSpace:      namespace,
			Name:           name,
			KeyType:        key_type,
			Environment:    environment,
			Version:        0,
			LifeTime:       lifetime,
			RotateDuration: rotate_duration,
			KEK:            plain_cache_kek.Name,
			OwnerAppkey:    owner_appkey,
		}

		if check, ok := server.cipher_key_len_map.Get(key_type); ok {
			cipher_key_len := check.(int)
			plain_cache_ak.AKPlaintext = qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(cipher_key_len))
		} else {
			return nil, errors.New("key Type Not supportked")
		}

		model_ak, err := PlainCacheAK2ModelAK(plain_cache_ak, kek_plaintext)

		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v", *model_ak, *plain_cache_kek))
			return nil, err
		}
		_, err = qkms_dal.GetDal().CreateAccessKey(ctx, model_ak)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, insert into database filed, encrypted_ak:%+v", model_ak))
			return nil, err
		}
		cipher_cache_ak, err := PlainCacheAK2CipherCacheAK(plain_cache_ak, server.cache_key)
		if err != nil {
			glog.Error("Create encrypted success but cache failed")
		}
		server.ak_map.Set(cmap_key, cipher_cache_ak)

		return plain_cache_ak, nil
	}
}

func (server *QkmsRealServer) UpdateAKInternal(ctx context.Context, namespace string, name string, ak_plaintext string, key_type string, environment string, owner_appkey string, version uint64) (*PlainCacheAK, error) {
	cmap_key := namespace + "#" + name + "#" + environment
	if check, ok := server.ak_map.Get(cmap_key); ok {
		cipher_cache_ak := check.(*CipherCacheAK)
		if version <= cipher_cache_ak.Version {
			return nil, errors.New("AK already modified")
		}
	}
	_, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, namespace, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", namespace, name, environment))
		return nil, err
	}
	kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", namespace, name, environment, *plain_cache_kek))
		return nil, err
	}
	plain_cache_ak := &PlainCacheAK{
		NameSpace:   namespace,
		Name:        name,
		AKPlaintext: ak_plaintext,
		KeyType:     key_type,
		Environment: environment,
		Version:     version,
		KEK:         plain_cache_kek.Name,
		OwnerAppkey: owner_appkey,
	}
	model_ak, err := PlainCacheAK2ModelAK(plain_cache_ak, kek_plaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, transfer failed, encrypted_ak:%+v", *plain_cache_ak))
		return nil, err
	}

	_, err = qkms_dal.GetDal().UpdateAccessKey(ctx, model_ak)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, insert into database filed, encrypted_ak:%+v", *model_ak))
		return nil, err
	}

	cipher_cache_ak, err := PlainCacheAK2CipherCacheAK(plain_cache_ak, server.cache_key)
	if err != nil {
		glog.Error("Create encrypted success but cache failed")
	} else {
		server.ak_map.Set(cmap_key, cipher_cache_ak)
	}

	return plain_cache_ak, nil

}

func (server *QkmsRealServer) GetAccessKeyIndexsInternal(ctx context.Context, namespace string) ([]*qkms_proto.GetAccessKeyIndexsReply_AccessKey, error) {
	aks, err := qkms_dal.GetDal().GetAccessKeyIndex(ctx, namespace)
	if err != nil {
		return nil, err
	}
	var reply_aks []*qkms_proto.GetAccessKeyIndexsReply_AccessKey
	for _, ak := range *aks {
		reply_ak := &qkms_proto.GetAccessKeyIndexsReply_AccessKey{
			NameSpace:   ak.NameSpace,
			Name:        ak.Name,
			Environment: ak.Environment,
		}
		reply_aks = append(reply_aks, reply_ak)
	}
	return reply_aks, nil
}
