package qkms_logic

import (
	"context"
	"fmt"
	qkms_common "qkms/common"
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
		reply.ErrorCode = qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR
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
	reply.ErrorCode = qkms_common.QKMS_ERROR_CODE_CREATE_KEK_SUCCESS
	return &reply, nil
}
