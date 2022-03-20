package qkms_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/golang/glog"
)

//@brief:填充明文
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密，根据密钥长度决定使用128/192/256
func AesCBCEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//@brief:AES解密，根据密钥长度决定使用128/192/256
func AesCBCDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func Base64Encoding(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func Base64Decoding(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

func Base64DecodeAesCBCDecrypt(src string, pass []byte) ([]byte, error) {
	old_enc_content, err := Base64Decoding(src)
	if err != nil {
		glog.Error(fmt.Sprintf("Base64DecodeAesCBCDecrypt failed! Base64 decode failed! %s", err.Error()))
		return nil, err
	}

	plain_content, err := AesCBCDecrypt(old_enc_content, pass)
	if err != nil {
		glog.Error(fmt.Sprintf("Base64DecodeAesCBCDecrypt failed! Decrypted failed! %s", err.Error()))
		return nil, err
	}
	return plain_content, nil
}
