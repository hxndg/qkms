package qkms_logic

import (
	"context"
	qkms_crypto "qkms/crypto"
	qkms_model "qkms/model"
	pb "qkms/proto"

	"github.com/golang/glog"
)

type PlainCacheAK struct {
	NameSpace   string
	Name        string
	PlainTextAK string
	KeyType     string
	Environment string
	Version     uint64
	KEKVersion  uint64
	OwnerAppkey string
}

type CipherCacheAK struct {
	NameSpace    string
	Name         string
	CipherTextAK string
	KeyType      string
	Srand        uint64
	TimeStamp    uint64
	Environment  string
	Version      uint64
	KEKVersion   uint64
	OwnerAppkey  string
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
	out.Srand, out.TimeStamp = qkms_crypto.GetSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.PlainTextAK)
	if err != nil {
		glog.Error("Transfer PlainCacheAK to CipherCacheAK failed! Can't decode base64 from, %+v", in)
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error("Transfer PlainCacheAK to CipherCacheAK failed! Can't Encrypt plaintextak from %+v, using key %s", in, qkms_crypto.Base64Encoding(key))
		return nil, err
	}
	out.CipherTextAK = qkms_crypto.Base64Encoding(ciphertext_ak)
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
	out.Srand, out.TimeStamp = qkms_crypto.GetSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.PlainTextAK)
	if err != nil {
		glog.Error("Transfer PlainCacheAK to model.AccessKey failed! Can't decode base64 from, %+v", in)
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error("Transfer PlainCacheAK to model.AccessKey failed! Can't Encrypt plaintextak from %+v, using key %s", in, qkms_crypto.Base64Encoding(key))
		return nil, err
	}
	out.CipherTextAK = qkms_crypto.Base64Encoding(ciphertext_ak)
	return &out, nil
}
func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *pb.ReadAccessKeyRequest) (*pb.ReadAccessKeyReply, error)
func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *pb.GenerateAccessKeyReply) (*pb.GenerateAccessKeyReply, error)
func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *pb.CreateAccessKeyRequest) (*pb.CreateAccessKeyRequest, error)
func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *pb.UpdateAccessKeyRequest) (*pb.UpdateAccessKeyReply, error)
func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *pb.RotateAccessKeyRequest) (*pb.RotateAccessKeyReply, error)
func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *pb.GrantAccessKeyAuthorizationRequest) (*pb.GrantAccessKeyAuthorizationReply, error)
