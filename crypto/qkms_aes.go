package qkms_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

func GenerateIV(bytes int) []byte {
	b := make([]byte, bytes)
	rand.Read(b)
	return b
}

func GeneratePass(bytes int) []byte {
	return GenerateIV(bytes)
}

func GenerateIVFromTwoNumber(srand uint64, timestamp uint64) []byte {
	default_iv := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	output_iv := make([]byte, len(default_iv))
	for i := 0; i < len(output_iv); i++ {
		output_iv[i] = byte((uint64(default_iv[i])*srand + timestamp) % 256)
	}
	return output_iv
}

func AesCTRDefaultIVEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Default IV
	iv := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	//CTR模式是不需要填充的，返回一个计数器模式的，底层采用block生成key流的srtream接口
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	//加密操作
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func AesCTRDefaultIVDecrypt(plaintext []byte, key []byte) ([]byte, error) {
	return AesCTRDefaultIVEncrypt(plaintext, key)
}

func AesCTREncrypt(plaintext []byte, iv []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//CTR模式是不需要填充的，返回一个计数器模式的，底层采用block生成key流的srtream接口
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	//加密操作
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func AesCTRDecrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error) {
	return AesCTREncrypt(ciphertext, iv, key)
}
