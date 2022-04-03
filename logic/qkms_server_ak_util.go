package qkms_logic

import (
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"
	qkms_model "qkms/model"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

type PlainCacheAK struct {
	NameSpace   string
	Name        string
	AKPlaintext string
	KeyType     string
	Environment string
	Version     uint64
	KEKVersion  uint64
	OwnerAppkey string
}

type CipherCacheAK struct {
	NameSpace    string
	Name         string
	AKCiphertext string
	KeyType      string
	Srand        uint64
	TimeStamp    uint64
	Environment  string
	Version      uint64
	KEKVersion   uint64
	OwnerAppkey  string
}

func ModelAK2CipherCacheAK(in *qkms_model.AccessKey, decypt_key []byte, encrypt_key []byte) (*CipherCacheAK, error) {
	ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(in.AKCiphertext, in.Srand, in.TimeStamp, decypt_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to CipherCacheAK failed! %+v", *in))
		return nil, err
	}
	out := CipherCacheAK{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		KEKVersion:  in.KEKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	ak_ciphertext, err := EncryptAESCtrBySrandTimeStamp(qkms_crypto.Base64Encoding(ak_plaintext), out.Srand, out.TimeStamp, encrypt_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to CipherCacheAK failed! Can't encrypt %+v, from %+v by key %s", out, *in, qkms_crypto.Base64Encoding(encrypt_key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ak_ciphertext)
	return &out, nil
}

func ModelAK2ProtoReadAKReply(in *qkms_model.AccessKey, key []byte) (*qkms_proto.ReadAccessKeyReply, error) {
	out := qkms_proto.ReadAccessKeyReply{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
	}
	ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(in.AKCiphertext, in.Srand, in.TimeStamp, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to ReadAccessKeyReply failed! %+v", *in))
		out.ErrorCode = qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR
		return &out, err
	}

	out.AKPlaintext = qkms_crypto.Base64Encoding(ak_plaintext)
	out.ErrorCode = qkms_common.QKMS_ERROR_CODE_READ_AK_SUCCESS
	return &out, nil
}

func PlainCacheAK2CipherCacheAK(in *PlainCacheAK, key []byte) (*CipherCacheAK, error) {
	out := CipherCacheAK{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		KEKVersion:  in.KEKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.AKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to CipherCacheAK failed! Can't decode base64 from, %+v", *in))
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to CipherCacheAK failed! Can't Encrypt AKPlaintext from %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ciphertext_ak)
	return &out, nil
}

func CipherCacheAK2PlainCacheAK(in *CipherCacheAK, key []byte) (*PlainCacheAK, error) {
	out := PlainCacheAK{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		KEKVersion:  in.KEKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(in.AKCiphertext, in.Srand, in.TimeStamp, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Decrypt CipherCacheAK failed ! CipherCacheAK %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.AKPlaintext = qkms_crypto.Base64Encoding(ak_plaintext)
	return &out, nil
}

func PlainCacheAK2ModelAK(in *PlainCacheAK, key []byte) (*qkms_model.AccessKey, error) {
	out := qkms_model.AccessKey{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		KEKVersion:  in.KEKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.AKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to model.AccessKey failed! Can't decode base64 from, %+v", in))
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to model.AccessKey failed! Can't Encrypt AKPlaintext from %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ciphertext_ak)
	return &out, nil
}
