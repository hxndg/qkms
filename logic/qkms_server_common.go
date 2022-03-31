package qkms_logic

import (
	"fmt"
	qkms_crypto "qkms/crypto"

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
