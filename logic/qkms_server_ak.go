package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

type PlainCacheAK struct {
	NameSpace   string
	Name        string
	AKPlaintext string
	KeyType     string
	Environment string
	Version     uint64
	KEKVersion  uint64
	OwnerAppkey string
}

type CipherCacheAK struct {
	NameSpace    string
	Name         string
	AKCiphertext string
	KeyType      string
	Srand        uint64
	TimeStamp    uint64
	Environment  string
	Version      uint64
	KEKVersion   uint64
	OwnerAppkey  string
}

func ModelAK2CipherCacheAK(in *qkms_model.AccessKey, decypt_key []byte, encrypt_key []byte) (*CipherCacheAK, error) {
	ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(in.AKCiphertext, in.Srand, in.TimeStamp, decypt_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to CipherCacheAK failed! %+v", *in))
		return nil, err
	}
	out := CipherCacheAK{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
		KEKVersion:  in.KEKVersion,
		OwnerAppkey: in.OwnerAppkey,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	ak_ciphertext, err := EncryptAESCtrBySrandTimeStamp(qkms_crypto.Base64Encoding(ak_plaintext), out.Srand, out.TimeStamp, encrypt_key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to CipherCacheAK failed! Can't encrypt %+v, from %+v by key %s", out, *in, qkms_crypto.Base64Encoding(encrypt_key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ak_ciphertext)
	return &out, nil
}

func ModelAK2ProtoReadAKReply(in *qkms_model.AccessKey, key []byte) (*qkms_proto.ReadAccessKeyReply, error) {
	out := qkms_proto.ReadAccessKeyReply{
		NameSpace:   in.NameSpace,
		Name:        in.Name,
		KeyType:     in.KeyType,
		Environment: in.Environment,
		Version:     in.Version,
	}
	ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(in.AKCiphertext, in.Srand, in.TimeStamp, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer ModelAK to ReadAccessKeyReply failed! %+v", *in))
		out.ErrorCode = QKMS_ERROR_CODE_INTERNAL_ERROR
		return &out, err
	}

	out.AKPlaintext = qkms_crypto.Base64Encoding(ak_plaintext)
	out.ErrorCode = QKMS_ERROR_CODE_AK_FOUND
	return &out, nil
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
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.AKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to CipherCacheAK failed! Can't decode base64 from, %+v", *in))
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to CipherCacheAK failed! Can't Encrypt AKPlaintext from %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ciphertext_ak)
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
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	plaintext_ak, err := qkms_crypto.Base64Decoding(in.AKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to model.AccessKey failed! Can't decode base64 from, %+v", in))
		return nil, err
	}
	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(plaintext_ak, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCacheAK to model.AccessKey failed! Can't Encrypt AKPlaintext from %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.AKCiphertext = qkms_crypto.Base64Encoding(ciphertext_ak)
	return &out, nil
}

func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *qkms_proto.ReadAccessKeyRequest) (*qkms_proto.ReadAccessKeyReply, error) {
	cmap_key := req.NameSpace + "#" + req.Environment
	// 先检索内存当中有没有缓存AK，如果缓存了就直接返回
	if check, ok := server.ak_map.Get(cmap_key); ok {
		//这里注意下encrypted_ak是CipherCacheAK类型
		cipher_cache_ak := check.(CipherCacheAK)

		ak_plaintext, err := DecryptedAESCtrBySrandTimeStamp(cipher_cache_ak.AKCiphertext, cipher_cache_ak.Srand, cipher_cache_ak.TimeStamp, server.cache_key)
		if err != nil {
			glog.Error(fmt.Sprintf("Decrypt CipherCacheAK failed ! CipherCacheAK %+v, using key %s", cipher_cache_ak, qkms_crypto.Base64Encoding(server.cache_key)))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
		}
		var reply qkms_proto.ReadAccessKeyReply
		reply.ErrorCode = QKMS_ERROR_CODE_AK_FOUND
		reply.NameSpace = cipher_cache_ak.NameSpace
		reply.Name = cipher_cache_ak.Name
		reply.AKPlaintext = qkms_crypto.Base64Encoding(ak_plaintext)
		reply.KeyType = cipher_cache_ak.KeyType
		reply.Environment = cipher_cache_ak.Environment
		reply.Version = cipher_cache_ak.Version

		return &reply, nil
	} else {
		//没有缓存，所以先从数据库当中取出来AK，再拿KEK读取再丢回去。
		//encrypted_ak*qkms_model.AccessKey类型
		encrypted_ak, err := qkms_dal.GetDal().AccquireAccessKey(ctx, req.NameSpace, req.Name, req.Environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get AK from database, request for namespace:%s name:%s, environment:%s", req.NameSpace, req.Name, req.Environment))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_AK_NOT_FOUND}, err
		}
		error_code, plain_cache_kek, err := server.ReadKEKByNamespaceAndVersion(ctx, encrypted_ak.NameSpace, encrypted_ak.Environment, encrypted_ak.KEKVersion)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't get related KEK for encrypted Ak, encrypted AK %+v", encrypted_ak))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: error_code}, err
		}
		kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Can't Decoding plain kek %+v, ", *plain_cache_kek))
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
		}
		cipher_cache_ak, err := ModelAK2CipherCacheAK(encrypted_ak, kek_plaintext, server.root_key)
		if err != nil {
			return &qkms_proto.ReadAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
		} else {
			server.ak_map.Set(cmap_key, *cipher_cache_ak)
		}
		reply, err := ModelAK2ProtoReadAKReply(encrypted_ak, kek_plaintext)
		return reply, err
	}
}
func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *qkms_proto.GenerateAccessKeyReply) (*qkms_proto.GenerateAccessKeyReply, error) {
	return nil, nil
}
func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *qkms_proto.CreateAccessKeyRequest) (*qkms_proto.CreateAccessKeyReply, error) {
	cmap_key := req.NameSpace + "#" + req.Environment
	// 先检索内存当中有没有缓存AK，如果有了就直接报错返回
	if _, ok := server.ak_map.Get(cmap_key); ok {
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_AK_ALREADY_EXIST}, errors.New("ak already exist")
	} else {
		//没有缓存，所以先从数据库当中取出来AK，再拿KEK读取再丢回去。
		//encrypted_ak*qkms_model.AccessKey类型
		error_code, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, req.NameSpace, req.Environment)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", req.NameSpace, req.Name, req.Environment))
			return &qkms_proto.CreateAccessKeyReply{ErrorCode: error_code}, err
		}
		kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", req.NameSpace, req.Name, req.Environment, *plain_cache_kek))
			return &qkms_proto.CreateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
		}
		encrypted_ak := qkms_model.AccessKey{
			NameSpace:   req.NameSpace,
			Name:        req.Name,
			KeyType:     req.KeyType,
			Environment: req.Environment,
			Version:     0,
			KEKVersion:  plain_cache_kek.Version,
			OwnerAppkey: "hxndgtest",
		}
		encrypted_ak.Srand, encrypted_ak.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
		ak_ciphertext, err := EncryptAESCtrBySrandTimeStamp(req.AKPlaintext, encrypted_ak.Srand, encrypted_ak.TimeStamp, kek_plaintext)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v", encrypted_ak, *plain_cache_kek))
			return &qkms_proto.CreateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
		}
		encrypted_ak.AKCiphertext = qkms_crypto.Base64Encoding(ak_ciphertext)
		error_code, err = qkms_dal.GetDal().CreateAccessKey(ctx, &encrypted_ak)
		if err != nil {
			glog.Error(fmt.Sprintf("Create AK failed, insert into database filed, encrypted_ak:%+v", encrypted_ak))
			return &qkms_proto.CreateAccessKeyReply{ErrorCode: error_code}, err
		} else {
			cipher_cache_ak, err := ModelAK2CipherCacheAK(&encrypted_ak, kek_plaintext, server.cache_key)
			if err != nil {
				glog.Error("Create encrypted success but cache failed")
			} else {
				server.ak_map.Set(cmap_key, *cipher_cache_ak)
			}
		}
		return &qkms_proto.CreateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_CREATE_AK_SUCCESS}, nil
	}
}

//这里注意更新请求的kek是
func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *qkms_proto.UpdateAccessKeyRequest) (*qkms_proto.UpdateAccessKeyReply, error) {
	cmap_key := req.NameSpace + "#" + req.Environment
	// 先检索内存当中有没有缓存AK，如果有了就直接报错返回
	if check, ok := server.ak_map.Get(cmap_key); ok {
		//这里注意下encrypted_ak是CipherCacheAK类型
		cipher_cache_ak := check.(CipherCacheAK)
		if req.Version <= cipher_cache_ak.Version {
			return &qkms_proto.UpdateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_UPDATE_AK_VERSION_TOO_OLD}, errors.New("ak already modified")
		}
	}
	//没有缓存，所以先从数据库当中取出来AK，再拿KEK读取再丢回去。
	//encrypted_ak*qkms_model.AccessKey类型
	error_code, plain_cache_kek, err := server.ReadKEKByNamespace(ctx, req.NameSpace, req.Environment)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, no related kek for database. Request for namespace:%s name:%s, environment:%s", req.NameSpace, req.Name, req.Environment))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: error_code}, err
	}
	kek_plaintext, err := qkms_crypto.Base64Decoding(plain_cache_kek.KEKPlaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Create AK failed, can't decode plain kek. Request for namespace:%s name:%s, environment:%s, kek: %+v", req.NameSpace, req.Name, req.Environment, *plain_cache_kek))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	encrypted_ak := qkms_model.AccessKey{
		NameSpace:   req.NameSpace,
		Name:        req.Name,
		KeyType:     req.KeyType,
		Environment: req.Environment,
		Version:     req.Version,
		KEKVersion:  plain_cache_kek.Version,
		OwnerAppkey: "hxndgtest",
	}
	encrypted_ak.Srand, encrypted_ak.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	ak_ciphertext, err := EncryptAESCtrBySrandTimeStamp(req.AKPlaintext, encrypted_ak.Srand, encrypted_ak.TimeStamp, kek_plaintext)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, can't encrypt ak, encrypted_ak:%+v, plain_cache_kek:%+v", encrypted_ak, *plain_cache_kek))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_INTERNAL_ERROR}, err
	}
	encrypted_ak.AKCiphertext = qkms_crypto.Base64Encoding(ak_ciphertext)
	error_code, err = qkms_dal.GetDal().UpdateAccessKey(ctx, &encrypted_ak)
	if err != nil {
		glog.Error(fmt.Sprintf("Update AK failed, insert into database filed, encrypted_ak:%+v", encrypted_ak))
		return &qkms_proto.UpdateAccessKeyReply{ErrorCode: error_code}, err
	} else {
		cipher_cache_ak, err := ModelAK2CipherCacheAK(&encrypted_ak, kek_plaintext, server.cache_key)
		if err != nil {
			glog.Error("Create encrypted success but cache failed")
		} else {
			server.ak_map.Set(cmap_key, *cipher_cache_ak)
		}
	}
	return &qkms_proto.UpdateAccessKeyReply{ErrorCode: QKMS_ERROR_CODE_UPDATE_AK_SUCCESS}, nil

}
func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *qkms_proto.RotateAccessKeyRequest) (*qkms_proto.RotateAccessKeyReply, error) {
	return nil, nil
}
func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *qkms_proto.GrantAccessKeyAuthorizationRequest) (*qkms_proto.GrantAccessKeyAuthorizationReply, error) {
	return nil, nil
}
