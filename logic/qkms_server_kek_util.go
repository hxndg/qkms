package qkms_logic

import (
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_model "qkms/model"

	"github.com/golang/glog"
)

// KEKPlaintext是经过base64编码的明文密钥
type PlainCacheKEK struct {
	Name         string
	KEKPlaintext string
	KeyType      string
	Environment  string
	RK           string
	OwnerAppkey  string
}

// KEKCiphertext是经过base64编码的密文密钥
type CipherCacheKEK struct {
	Name          string
	KEKCiphertext string
	KeyType       string
	Srand         uint64
	TimeStamp     uint64
	Environment   string
	RK            string
	OwnerAppkey   string
}

func PlainCacheKEK2CipherCacheKEK(in *PlainCacheKEK, key []byte) (*CipherCacheKEK, error) {
	out := CipherCacheKEK{
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		RK:          in.RK,
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
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		RK:          in.RK,
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
