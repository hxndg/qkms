package main

/*
import (
	"net"

	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"



	"github.com/golang/glog"

	pb "qkms/proto"
)

type qkmsRealServer struct {
	pb.UnimplementedQkmsServer
}

func (server *qkmsRealServer) ReadAccessKey(ctx context.Context, req *pb.ReadAccessKeyRequest) (*pb.ReadAccessKeyReply, error)
func (server *qkmsRealServer) GenerateAccessKey(ctx context.Context, req *pb.GenerateAccessKeyReply) (*pb.GenerateAccessKeyReply, error)
func (server *qkmsRealServer) CreateAccessKey(ctx context.Context, req *pb.CreateAccessKeyRequest) (*pb.CreateAccessKeyRequest, error)
func (server *qkmsRealServer) UpdateAccessKey(ctx context.Context, req *pb.UpdateAccessKeyRequest) (*pb.UpdateAccessKeyReply, error)
func (server *qkmsRealServer) RotateAccessKey(ctx context.Context, req *pb.RotateAccessKeyRequest) (*pb.RotateAccessKeyReply, error)
func (server *qkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *pb.GrantAccessKeyAuthorizationRequest) (*pb.GrantAccessKeyAuthorizationReply, error)

func main() {
	lis, err := net.Listen("tcp", "127.0.0.1:21157")
	if err != nil {
		glog.Error("Can't Create Server, %s", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterQkmsServer(grpcServer, &qkmsRealServer{})

	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		glog.Errorln("")
	}
}
*/

import (
	"context"
	"fmt"
	"github.com/golang/glog"
	"os"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"
)

func main() {

	var db_config qkms_dal.DBConfig
	db_config.DbName = "postgres"
	db_config.Host = "127.0.0.1"
	db_config.Username = "xiaonan"
	db_config.Port = 5432
	db_config.Password = "12345678"

	qkms_dal.MustInit(db_config)

	root_key := "abcdefghijklmnop"
	var kek qkms_model.KeyEncryptionKey
	kek.Environment = "test"
	kek.KeyType = "AES"
	kek.NameSpace = "hxn_test_namespace"
	kek.OwnerAppkey = "abc"
	kek.RKVersion = 0

	enc_content, enc_error := qkms_crypto.AesCBCEncrypt([]byte("hello worldddddddddddddddd"), []byte(root_key))
	if enc_error != nil {
		glog.Error("Can't Create Server, %s", enc_error)
	}
	kek.EncryptedKEK = qkms_crypto.Base64Encoding(enc_content)
	glog.Info(fmt.Sprintf("Input KEK is %+v, plain_kek is %s", kek, "hello worldddddddddddddddd"))

	_, err := qkms_dal.GetDal().CreateKeyEncryptionKey(context.Background(), &kek)
	if err != nil {
		glog.Error("Can't insert new kek")
		os.Exit(1)
	}

	read_kek, err := qkms_dal.GetDal().AccquireKeyEncryptionKey(context.Background(), kek.NameSpace, kek.Environment)
	if err != nil {
		glog.Error("Can't read created kek")
		os.Exit(1)
	}
	glog.Info(fmt.Sprintf("Output KEK is %+v", *read_kek))

	base64_enc_content, err := qkms_crypto.Base64Decoding(read_kek.EncryptedKEK)
	if err != nil {
		glog.Error("Base 64 decode failed for kek's encrypted kek")
	}
	dec_content, dec_err := qkms_crypto.AesCBCDecrypt(base64_enc_content, []byte(root_key))
	if dec_err != nil {
		glog.Error("Can't Create Server, %s", dec_err)
	}
	glog.Info(fmt.Sprintf("Input plain KEK is %s", string(dec_content)))

	os.Exit(0)
}
