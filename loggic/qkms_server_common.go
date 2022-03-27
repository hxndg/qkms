package qkms_logic

import (
	qkms_crypto "qkms/crypto"

	"github.com/golang/glog"
)

func DecryptedAESCtrBySrandTimeStamp(base64_ciphertext string, srand uint64, timestamp uint64, key []byte) ([]byte, error) {
	ciphertext, err := qkms_crypto.Base64Decoding(base64_ciphertext)
	if err != nil {
		glog.Error("Can't decode base64 for ciphertext, %s", base64_ciphertext)
		return nil, err
	}
	iv := qkms_crypto.GenerateIVFromTwoNumber(srand, timestamp)
	plaintext, err := qkms_crypto.AesCTRDecrypt(ciphertext, iv, key)
	if err != nil {
		glog.Error("Can't decrypted for ciphertext %s, using key %s", base64_ciphertext, qkms_crypto.Base64Encoding(key))
		return nil, err
	}
	return plaintext, nil
}

func EncryptAESCtrBySrandTimeStamp(base64_plaintext string, srand uint64, timestamp uint64, key []byte) ([]byte, error) {
	plaintext, err := qkms_crypto.Base64Decoding(base64_plaintext)
	if err != nil {
		glog.Error("Can't decode base64 for plaintext, %s", base64_plaintext)
		return nil, err
	}
	iv := qkms_crypto.GenerateIVFromTwoNumber(srand, timestamp)
	ciphertext, err := qkms_crypto.AesCTREncrypt(plaintext, iv, key)
	if err != nil {
		glog.Error("Can't encrypt for plaintext %s, using key %s", base64_plaintext, qkms_crypto.Base64Encoding(key))
		return nil, err
	}
	return ciphertext, nil
}

const QKMS_ERROR_CODE_AK_FOUND = 200
const QKMS_ERROR_CODE_AK_NOT_FOUND = 201
const QKMS_ERROR_CODE_AK_ALREADY_EXIST = 202
const QKMS_ERROR_CODE_CREATE_AK_SUCCESS = 203
const QKMS_ERROR_CODE_UPDATE_AK_VERSION_TOO_OLD = 204
const QKMS_ERROR_CODE_UPDATE_AK_SUCCESS = 205
const QKMS_ERROR_CODE_KEK_NOT_FOUND = 404
const QKMS_ERROR_CODE_KEK_TOO_OLD = 405
const QKMS_ERROR_CODE_KEK_TOO_NEW = 406
const QKMS_ERROR_CODE_KEK_VERSION_MISMATCH = 407
const QKMS_ERROR_CODE_KEK_FOUND = 408
const QKMS_ERROR_CODE_INTERNAL_ERROR = 500
const QKMS_ERROR_CODE_CREATE_KEK_FAILED = 500
const QKMS_ERROR_CODE_CREATE_KEK_SUCCESS = 501
