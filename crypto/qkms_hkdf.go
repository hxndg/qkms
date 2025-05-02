package qkms_crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// salt 需要和hash size一样长，info就随意了。secret为使用的master secret
// len 为要生成的密钥的长度
func Sha256HKDF(secret []byte, info []byte, length int) ([]byte, error) {
	hash := sha256.New
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hkdf := hkdf.New(hash, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// salt 需要和hash size一样长，info就随意了。secret为使用的master secret
// len 为要生成的密钥的长度
func HKDF(hash func() hash.Hash, secret []byte, salt []byte, info []byte, length int) ([]byte, error) {
	if len(salt) != hash().Size() {
		return nil, errors.New("HKDF Error: salt length mismatch hash size")
	}
	hkdf := hkdf.New(hash, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}
