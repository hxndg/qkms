package qkms_logic

import (
	"fmt"
	qkms_crypto "qkms/crypto"
	"strings"

	"github.com/golang/glog"
)

func DecryptedAESCtrBySrandTimeStamp(base64_ciphertext string, srand uint64, timestamp uint64, key []byte) ([]byte, error) {
	ciphertext, err := qkms_crypto.Base64Decoding(base64_ciphertext)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decode base64 for ciphertext, %s", base64_ciphertext))
		return nil, err
	}
	iv := qkms_crypto.GenerateIVFromTwoNumber(srand, timestamp)
	plaintext, err := qkms_crypto.AesCTRDecrypt(ciphertext, iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decrypted for ciphertext %s, using key %s", base64_ciphertext, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	return plaintext, nil
}

func EncryptAESCtrBySrandTimeStamp(base64_plaintext string, srand uint64, timestamp uint64, key []byte) ([]byte, error) {
	plaintext, err := qkms_crypto.Base64Decoding(base64_plaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't decode base64 for plaintext, %s", base64_plaintext))
		return nil, err
	}
	iv := qkms_crypto.GenerateIVFromTwoNumber(srand, timestamp)
	ciphertext, err := qkms_crypto.AesCTREncrypt(plaintext, iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Can't encrypt for plaintext %s, using key %s", base64_plaintext, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	return ciphertext, nil
}

func Split2GetValue(in string, sep string, kv_sep string, key string) *string {
	in_slice := strings.Split(in, sep)
	for _, kv := range in_slice {
		kv_slice := strings.Split(kv, kv_sep)
		if len(kv_slice) != 2 {
			continue
		}
		if kv_slice[0] == key {
			return &kv_slice[1]
		}
	}
	return nil
}
