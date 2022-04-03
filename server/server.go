package main

import (
	"context"
	"fmt"
	"os"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_logic "qkms/logic"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
)

func main() {
	/*
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
	*/
	var db_config qkms_dal.DBConfig
	db_config.DbName = "postgres"
	db_config.Host = "127.0.0.1"
	db_config.Username = "xiaonan"
	db_config.Port = 5432
	db_config.Password = "12345678"
	var server qkms_logic.QkmsRealServer
	err := server.Init("server.crt", "server.key", db_config)
	if err != nil {
		glog.Error("Can't Init QkmsRealServer for", err.Error())
		os.Exit(1)
	}
	create_kek_req := qkms_proto.CreateKeyEncryptionKeyRequest{
		NameSpace:   "kek",
		Environment: "test",
	}
	create_ak_req := qkms_proto.CreateAccessKeyRequest{
		NameSpace:   "kek",
		Name:        "new_ak",
		AKPlaintext: qkms_crypto.Base64Encoding([]byte("hxn has a big dick")),
		KeyType:     "opaque",
		Environment: "test",
	}
	_, err = server.CreateAccessKey(context.Background(), &create_ak_req)
	if err != nil {
		glog.Error("Creat ak failed as expected")
	}
	_, err = server.CreateKeyEncryptionKey(context.Background(), &create_kek_req)
	if err != nil {
		glog.Error("Creat kek failed!")
		os.Exit(1)
	}
	create_kek_req.Environment = "doggy"
	_, err = server.CreateKeyEncryptionKey(context.Background(), &create_kek_req)
	if err != nil {
		glog.Error("Creat kek failed!")
		os.Exit(1)
	}
	_, err = server.CreateAccessKey(context.Background(), &create_ak_req)
	if err != nil {
		glog.Error("Creat ak failed!")
		os.Exit(1)
	}
	read_ak_req := qkms_proto.ReadAccessKeyRequest{
		NameSpace:   "kek",
		Name:        "new_ak",
		Environment: "test",
	}
	update_kar_req := qkms_proto.GrantAccessKeyAuthorizationRequest{
		NameSpace:   "kek",
		Name:        "new_ak",
		Environment: "test",
		Appkey:      "hxndg",
		Behavior:    "read",
	}
	// _, err = server.GrantAccessKeyAuthorization(context.Background(), &update_kar_req)
	// if err != nil {
	// 	glog.Error("Update kar failed!")
	// 	os.Exit(1)
	// }
	update_kar_req.Behavior = "write"
	_, err = server.GrantAccessKeyAuthorization(context.Background(), &update_kar_req)
	if err != nil {
		glog.Error("Update kar failed!")
		os.Exit(1)
	}
	_, err = server.ReadAccessKey(context.Background(), &read_ak_req)
	if err != nil {
		glog.Error("Read ak asexpected!")
	}
	_, err = server.ReadAccessKey(context.Background(), &read_ak_req)
	if err != nil {
		glog.Error("Read ak asexpected!")
	}
	_, err = server.GrantAccessKeyAuthorization(context.Background(), &update_kar_req)
	if err != nil {
		glog.Error("Update kar failed!")
		os.Exit(1)
	}
	update_kar_req.Behavior = "read"
	_, err = server.GrantAccessKeyAuthorization(context.Background(), &update_kar_req)
	if err != nil {
		glog.Error("Update kar failed!")
		os.Exit(1)
	}
	read_ak_reply, err := server.ReadAccessKey(context.Background(), &read_ak_req)
	if err != nil {
		glog.Error("Read ak failed!")
		os.Exit(1)
	} else {
		ak_plaintext, err := qkms_crypto.Base64Decoding(read_ak_reply.AKPlaintext)
		if err != nil {
			glog.Error("Decode base64 failed")
		} else {
			glog.Info(fmt.Sprintf("Read ak success! Namespace:%s, Name:%s, KeyType:%s, Environment:%s, AKPlainText:%s", read_ak_reply.NameSpace, read_ak_reply.Name, read_ak_reply.KeyType, read_ak_reply.Environment, ak_plaintext))
		}
	}

	update_ak_request := qkms_proto.UpdateAccessKeyRequest{
		NameSpace:   "kek",
		Name:        "new_ak",
		AKPlaintext: qkms_crypto.Base64Encoding([]byte("hxn has a small dick")),
		KeyType:     "opaque",
		Environment: "test",
		Version:     1,
	}
	_, err = server.UpdateAccessKey(context.Background(), &update_ak_request)
	if err != nil {
		glog.Error("Update ak failed!")
		os.Exit(1)
	}
	read_ak_reply, err = server.ReadAccessKey(context.Background(), &read_ak_req)
	if err != nil {
		glog.Error("Read ak failed!")
		os.Exit(1)
	} else {
		ak_plaintext, err := qkms_crypto.Base64Decoding(read_ak_reply.AKPlaintext)
		if err != nil {
			glog.Error("Decode base64 failed")
		} else {
			glog.Info(fmt.Sprintf("Read ak success! Namespace:%s, Name:%s, KeyType:%s, Environment:%s, AKPlainText:%s", read_ak_reply.NameSpace, read_ak_reply.Name, read_ak_reply.KeyType, read_ak_reply.Environment, ak_plaintext))
		}
	}
}
