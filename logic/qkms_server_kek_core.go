package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"

	"github.com/golang/glog"
)

// 内存中的KEK存储在concurrentmap当中
// key为Name#Environment，value为EncryptedCacheKEK
func (server *QkmsRealServer) ReadKEKByNamespace(ctx context.Context, namespace string, environment string) (uint64, *PlainCacheKEK, error) {
	namespace_info, err := qkms_dal.GetDal().AccquireNamespace(ctx, namespace, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get namespace from database, namespace: %s, environment: %s", namespace, environment))
		return qkms_common.QKMS_ERROR_CODE_FIND_NAMESPACE_FAILED, nil, err

	}

	cmap_key := namespace_info.KEK + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(*CipherCacheKEK)

		kek_plaintext, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		plain_cache_kek := PlainCacheKEK{
			Name:         encrypted_kek.Name,
			KEKPlaintext: qkms_crypto.Base64Encoding(kek_plaintext),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			RK:           encrypted_kek.RK,
			OwnerAppkey:  encrypted_kek.OwnerAppkey,
		}
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, &plain_cache_kek, nil
	} else {
		//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
		encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, namespace_info.KEK, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get kek from database, namespace: %s, environment: %s", namespace, environment))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		kek_plaintext, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.root_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.root_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}

		plain_cache_kek := &PlainCacheKEK{
			Name:         encrypted_kek.Name,
			KEKPlaintext: qkms_crypto.Base64Encoding(kek_plaintext),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			RK:           encrypted_kek.RK,
			OwnerAppkey:  encrypted_kek.OwnerAppkey,
		}
		cipher_cached_kek, err := PlainCacheKEK2CipherCacheKEK(plain_cache_kek, server.cache_key)
		if err != nil {
			glog.Error("Can't Transfer!")
		} else {
			server.kek_map.Set(cmap_key, cipher_cached_kek)
		}
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, plain_cache_kek, nil
	}
}

func (server *QkmsRealServer) ReadKEKByName(ctx context.Context, name string, environment string) (uint64, *PlainCacheKEK, error) {
	cmap_key := name + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(*CipherCacheKEK)

		plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		plain_cache_kek := PlainCacheKEK{
			Name:         encrypted_kek.Name,
			KEKPlaintext: qkms_crypto.Base64Encoding(plaintext_kek),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			RK:           encrypted_kek.RK,
			OwnerAppkey:  encrypted_kek.OwnerAppkey,
		}
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, &plain_cache_kek, nil
	}

	//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
	encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, name, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get kek from database, name: %s, environment: %s", name, environment))
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
	}
	plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.root_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.root_key)))
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
	}
	plain_cache_kek := &PlainCacheKEK{
		Name:         encrypted_kek.Name,
		KEKPlaintext: qkms_crypto.Base64Encoding(plaintext_kek),
		KeyType:      encrypted_kek.KeyType,
		Environment:  encrypted_kek.Environment,
		RK:           encrypted_kek.RK,
		OwnerAppkey:  encrypted_kek.OwnerAppkey,
	}
	cached_kek, err := PlainCacheKEK2CipherCacheKEK(plain_cache_kek, server.cache_key)
	if err != nil {
		glog.Error("Can't Transfer!")
	} else {
		server.kek_map.Set(cmap_key, cached_kek)
	}

	return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, plain_cache_kek, nil

}

func (server *QkmsRealServer) CreateKEKInternal(ctx context.Context, name string, environment string, key_type string, ownerappkey string) (*PlainCacheKEK, error) {
	cmap_key := name + "#" + environment
	plain_cache_kek := PlainCacheKEK{
		Name:         name,
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
	_, err = qkms_dal.GetDal().CreateKeyEncryptionKey(ctx, cipher_kek)
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
