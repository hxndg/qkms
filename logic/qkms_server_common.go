package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"
	"strings"

	"github.com/golang/glog"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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
	glog.Info(in)
	in_slice := strings.Split(in, sep)
	for _, kv := range in_slice {
		glog.Info(kv)
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

func LoadAppKey(ctx context.Context) (*string, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Load appkey failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return nil, errors.New("invalid cert")
		}
		return ownerappkey, nil
	}
	return nil, errors.New("missing auth info")
}

func LoadUser(ctx context.Context) (*string, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_USER)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Load verion failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return nil, errors.New("invalid cert")
		}
		return ownerappkey, nil
	}
	return nil, errors.New("missing auth info")
}

func LoadVersion(ctx context.Context) (*string, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_VERSION)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Load verion failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return nil, errors.New("invalid cert")
		}
		return ownerappkey, nil
	}
	return nil, errors.New("missing auth info")
}
