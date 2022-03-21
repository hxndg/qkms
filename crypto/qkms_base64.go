package qkms_crypto

import (
	"encoding/base64"
)

func Base64Encoding(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func Base64Decoding(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}
