package main

import (
	"context"
	"os"
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
	err := server.Init("cert", "key", db_config)
	if err != nil {
		glog.Error("Can't Init QkmsRealServer")
		os.Exit(1)
	}
	create_kek_req := qkms_proto.CreateKeyEncryptionKeyRequest{
		NameSpace:   "kek",
		Environment: "test",
	}
	create_kek_reply, err := server.CreateKeyEncryptionKey(context.Background(), &req)
}
