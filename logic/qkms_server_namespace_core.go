package qkms_logic

import (
	"context"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	"time"

	"github.com/golang/glog"
)

func ServerHasNameSpace(namespace string, environment string) bool {
	return true
}

func (server *QkmsRealServer) CreateNameSpaceInternal(ctx context.Context, namespace string, environment string, ownerappkey string) (*PlainCacheKEK, error) {
	// 理论应该先检索内存当中有没有缓存的namespace，如果有了就直接报错返回，这里直接放弃让数据库去重
	// namespace not exists, create it, fisrt create a KEK for it
	currentTime := time.Now().Unix()
	kek_name := fmt.Sprintf("%s-%s-%s-%d", namespace, environment, "kek", currentTime)
	cmap_key := kek_name + "#" + environment
	plain_cache_kek := PlainCacheKEK{
		Name:         kek_name,
		KEKPlaintext: qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(16)),
		KeyType:      "AES-CTR-128",
		Environment:  environment,
		RK:           "default",
		OwnerAppkey:  ownerappkey,
	}
	cipher_kek, err := PlainCacheKEK2ModelKEK(&plain_cache_kek, server.root_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer plain cache kek to  model kek failed, plain cache kek %+v, using key %s", plain_cache_kek, qkms_crypto.Base64Encoding(server.root_key)))
		return nil, err
	}
	_, err = qkms_dal.GetDal().CreateNameSpaceAndKeyEncryptionKey(ctx, namespace, environment, cipher_kek)
	if err != nil {
		glog.Error(fmt.Sprintf("Create model kek failed, plain model kek %+v, using key %s", *cipher_kek, qkms_crypto.Base64Encoding(server.root_key)))
		return nil, err
	}

	cached_kek, err := PlainCacheKEK2CipherCacheKEK(&plain_cache_kek, server.cache_key)
	if err != nil {
		glog.Error("Can't Transfer!")
	} else {
		server.kek_map.Set(cmap_key, cached_kek)
	}
	return &plain_cache_kek, nil
}

func (server *QkmsRealServer) ReadNameSpaceInternal(ctx context.Context, name string, environment string) (*NamespaceInfo, error) {

	namespace_info, err := qkms_dal.GetDal().AccquireNamespace(ctx, name, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get namespace from database, name: %s, environment: %s", name, environment))
		return nil, err
	}
	return &NamespaceInfo{
		Name:        namespace_info.Name,
		Environment: namespace_info.Environment,
		OwnerAppkey: namespace_info.OwnerAppkey,
		KEK:         namespace_info.KEK,
	}, nil
}

func (server *QkmsRealServer) UpdateNameSpaceInfoInternal(ctx context.Context, name string, environment string, kek string, ownerappkey string) error {

	_, err := qkms_dal.GetDal().UpdateNameSpace(ctx, name, environment, kek, ownerappkey)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get namespace from database, name: %s, environment: %s", name, environment))
		return err
	}
	return nil
}
