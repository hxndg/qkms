package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

// KEKPlaintext是经过base64编码的明文密钥
type PlainCacheKEK struct {
	NameSpace    string
	KEKPlaintext string
	KeyType      string
	Environment  string
	Version      uint64
	RKVersion    uint64
	OwnerAppkey  string
}

// KEKCiphertext是经过base64编码的密文密钥
type CipherCacheKEK struct {
	NameSpace     string
	KEKCiphertext string
	KeyType       string
	Srand         uint64
	TimeStamp     uint64
	Environment   string
	Version       uint64
	RKVersion     uint64
	OwnerAppkey   string
}

func PlainCacheKEK2CipherCacheKEK(in *PlainCacheKEK, key []byte) (*CipherCacheKEK, error) {
	out := CipherCacheKEK{
		NameSpace:   in.NameSpace,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		RKVersion:   in.RKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	kek_plaintext, err := qkms_crypto.Base64Decoding(in.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decode base64 for plaincachekek, %+v", in))
		return nil, err
	}
	kek_ciphertext, err := qkms_crypto.AesCTREncrypt(kek_plaintext, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't encrypt for encrypted cache kek, plaincachekey is %+v, using key %s", in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.KEKCiphertext = qkms_crypto.Base64Encoding(kek_ciphertext)
	return &out, nil
}

func PlainCacheKEK2ModelKEK(in *PlainCacheKEK, key []byte) (*qkms_model.KeyEncryptionKey, error) {
	out := qkms_model.KeyEncryptionKey{
		NameSpace:   in.NameSpace,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		RKVersion:   in.RKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	kek_plaintext, err := qkms_crypto.Base64Decoding(in.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decode base64 for plaincachekek, %+v", in))
		return nil, err
	}
	kek_ciphertext, err := qkms_crypto.AesCTREncrypt(kek_plaintext, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't encrypt for encrypted cache kek, plaincachekey is %+v, using key %s", in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.KEKCiphertext = qkms_crypto.Base64Encoding(kek_ciphertext)
	return &out, nil
}

// 内存中的KEK存储在concurrentmap当中
// key为Namespace#Environment，value为EncryptedCacheKEK
func (server *QkmsRealServer) ReadKEKByNamespace(ctx context.Context, namespace string, environment string) (uint64, *PlainCacheKEK, error) {
	cmap_key := namespace + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(CipherCacheKEK)

		kek_plaintext, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
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
		return QKMS_ERROR_CODE_KEK_FOUND, &plain_cache_kek, nil
	} else {
		//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
		encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, namespace, environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get kek from database, namespace: %s, environment: %s", namespace, environment))
			return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
		}
		kek_plaintext, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.root_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.root_key)))
			return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
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
		cached_kek, err := PlainCacheKEK2CipherCacheKEK(&plain_cache_kek, server.cache_key)
		if err != nil {
			glog.Error("Can't Transfer!")
		} else {
			server.kek_map.Set(cmap_key, *cached_kek)
		}
		return QKMS_ERROR_CODE_KEK_FOUND, &plain_cache_kek, nil
	}
}

func (server *QkmsRealServer) ReadKEKByNamespaceAndVersion(ctx context.Context, namespace string, environment string, version uint64) (uint64, *PlainCacheKEK, error) {
	cached_version := uint64(0)
	cmap_key := namespace + "#" + environment
	if check, ok := server.kek_map.Get(cmap_key); ok {
		//这里注意下encrypted_kek是EncryptedCacheKEK类型
		encrypted_kek := check.(CipherCacheKEK)
		cached_version = encrypted_kek.Version
		if version < encrypted_kek.Version {
			// 请求老版本的kek，理论上不太可能。因为如果KEK是新版本的，那么所有的AK应该是也更新成新版本了。
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
			return QKMS_ERROR_CODE_KEK_VERSION_MISMATCH, nil, errors.New("kek version mismatch")
		}
		if version == encrypted_kek.Version {
			plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.cache_key)
			if err != nil {
				glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.cache_key)))
				return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
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
			return QKMS_ERROR_CODE_KEK_FOUND, &plain_cache_kek, nil
		}
	}

	//这里注意下encrypted_kek是*qkms_model.KeyEncryptionKey类型
	encrypted_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(ctx, namespace, environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't get kek from database, namespace: %s, environment: %s", namespace, environment))
		return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
	}
	//上面要么没查到，要么查到了但是版本很老,如果没查到那么cached_version为0，如果查到了但是比较老我们也还会插入到本地内存。
	if encrypted_kek.Version > cached_version {
		plaintext_kek, err := DecryptedAESCtrBySrandTimeStamp(encrypted_kek.KEKCiphertext, encrypted_kek.Srand, encrypted_kek.TimeStamp, server.root_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't decrypted for encryptedkek %+v, using key %s", encrypted_kek, qkms_crypto.Base64Encoding(server.root_key)))
			return QKMS_ERROR_CODE_INTERNAL_ERROR, nil, err
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
		cached_kek, err := PlainCacheKEK2CipherCacheKEK(&plain_cache_kek, server.cache_key)
		if err != nil {
			glog.Error("Can't Transfer!")
		} else {
			server.kek_map.Set(cmap_key, *cached_kek)
		}
		if version == encrypted_kek.Version {
			return QKMS_ERROR_CODE_KEK_FOUND, &plain_cache_kek, nil
		}
	}
	return QKMS_ERROR_CODE_KEK_VERSION_MISMATCH, nil, errors.New("kek version mismatch")
}

func (server *QkmsRealServer) CreateKeyEncryptionKey(ctx context.Context, req *qkms_proto.CreateKeyEncryptionKeyRequest) (*qkms_proto.CreateKeyEncryptionKeyReply, error) {
	cmap_key := req.NameSpace + "#" + req.Environment
	var reply qkms_proto.CreateKeyEncryptionKeyReply
	plain_cache_kek := PlainCacheKEK{
		NameSpace:    req.NameSpace,
		KEKPlaintext: qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(16)),
		KeyType:      "AES",
		Environment:  req.Environment,
		Version:      0,
		RKVersion:    0,
		OwnerAppkey:  "hxntest",
	}
	cipher_kek, err := PlainCacheKEK2ModelKEK(&plain_cache_kek, server.root_key)
	if err != nil {
		reply.ErrorCode = QKMS_ERROR_CODE_CREATE_KEK_FAILED
		return &reply, err
	} else {
		error_code, err := qkms_dal.GetDal().CreateKeyEncryptionKey(ctx, cipher_kek)
		if err != nil {
			reply.ErrorCode = uint64(error_code)
			return &reply, err
		}
	}

	cached_kek, err := PlainCacheKEK2CipherCacheKEK(&plain_cache_kek, server.cache_key)
	if err != nil {
		glog.Error("Can't Transfer!")
	} else {
		server.kek_map.Set(cmap_key, *cached_kek)
	}
	reply.ErrorCode = QKMS_ERROR_CODE_CREATE_KEK_SUCCESS
	return &reply, nil

}
