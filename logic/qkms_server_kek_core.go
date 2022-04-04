package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"

	"github.com/golang/glog"
)

// 内存中的KEK存储在concurrentmap当中
// key为Namespace#Environment，value为EncryptedCacheKEK
func (server *QkmsRealServer) ReadKEKByNamespace(ctx context.Context, namespace string, environment string) (uint64, *PlainCacheKEK, error) {
	cmap_key := namespace + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(*CipherCacheKEK)

		kek_plaintext, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		plain_cache_kek := PlainCacheKEK{
			NameSpace:    encrypted_kek.NameSpace,
			KEKPlaintext: qkms_crypto.Base64Encoding(kek_plaintext),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			Version:      encrypted_kek.Version,
			RKVersion:    encrypted_kek.RKVersion,
			OwnerAppkey:  encrypted_kek.OwnerAppkey,
		}
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, &plain_cache_kek, nil
	} else {
		//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
		encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, namespace, environment)
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
			NameSpace:    encrypted_kek.NameSpace,
			KEKPlaintext: qkms_crypto.Base64Encoding(kek_plaintext),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			Version:      encrypted_kek.Version,
			RKVersion:    encrypted_kek.RKVersion,
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

func (server *QkmsRealServer) ReadKEKByNamespaceAndVersion(ctx context.Context, namespace string, environment string, version uint64) (uint64, *PlainCacheKEK, error) {
	cached_version := uint64(0)
	cmap_key := namespace + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(*CipherCacheKEK)
		cached_version = encrypted_kek.Version
		if version < encrypted_kek.Version {
			// 请求老版本的kek，理论上不太可能。因为如果KEK是新版本的，那么所有的AK应该是也更新成新版本了。
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_VERSION_MISMATCH, nil, errors.New("kek version mismatch")
		}
		if version == encrypted_kek.Version {
			plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
			if err != nil {
				glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
				return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
			}
			plain_cache_kek := PlainCacheKEK{
				NameSpace:    encrypted_kek.NameSpace,
				KEKPlaintext: qkms_crypto.Base64Encoding(plaintext_kek),
				KeyType:      encrypted_kek.KeyType,
				Environment:  encrypted_kek.Environment,
				Version:      encrypted_kek.Version,
				RKVersion:    encrypted_kek.RKVersion,
				OwnerAppkey:  encrypted_kek.OwnerAppkey,
			}
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, &plain_cache_kek, nil
		}
	}

	//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
	encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, namespace, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get kek from database, namespace: %s, environment: %s", namespace, environment))
		return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
	}
	//上面要么没查到，要么查到了但是版本很老,如果没查到那么cached_version为0，如果查到了但是比较老我们也还会插入到本地内存。
	if encrypted_kek.Version > cached_version {
		plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.root_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.root_key)))
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		plain_cache_kek := &PlainCacheKEK{
			NameSpace:    encrypted_kek.NameSpace,
			KEKPlaintext: qkms_crypto.Base64Encoding(plaintext_kek),
			KeyType:      encrypted_kek.KeyType,
			Environment:  encrypted_kek.Environment,
			Version:      encrypted_kek.Version,
			RKVersion:    encrypted_kek.RKVersion,
			OwnerAppkey:  encrypted_kek.OwnerAppkey,
		}
		cached_kek, err := PlainCacheKEK2CipherCacheKEK(plain_cache_kek, server.cache_key)
		if err != nil {
			glog.Error("Can't Transfer!")
		} else {
			server.kek_map.Set(cmap_key, cached_kek)
		}
		if version == encrypted_kek.Version {
			return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_FOUND, plain_cache_kek, nil
		}
	}
	return qkms_common.QKMS_ERROR_CODE_INTERNAL_KEK_VERSION_MISMATCH, nil, errors.New("kek version mismatch")
}

func (server *QkmsRealServer) CreateKEKInternal(ctx context.Context, namespace string, environment string) (*PlainCacheKEK, error) {
	cmap_key := namespace + "#" + environment
	plain_cache_kek := PlainCacheKEK{
		NameSpace:    namespace,
		KEKPlaintext: qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(16)),
		KeyType:      "AESCTR",
		Environment:  environment,
		Version:      0,
		RKVersion:    0,
		OwnerAppkey:  "hxndg",
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
