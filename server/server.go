package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	qkms_dal "qkms/dal"
	qkms_logic "qkms/logic"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	var db_config qkms_dal.DBConfig
	db_config.DbName = "postgres"
	db_config.Host = "127.0.0.1"
	db_config.Username = "xiaonan"
	db_config.Port = 5432
	db_config.Password = "12345678"
	var qkms_server qkms_logic.QkmsRealServer
	err := qkms_server.Init("server.crt", "server.key", db_config)
	if err != nil {
		glog.Error("Can't Init QkmsRealServer for", err.Error())
		panic(err)
	}

	cert, err := tls.LoadX509KeyPair("credentials/server/server.pem", "credentials/server/server.key")
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	rootBuf, err := ioutil.ReadFile("credentials/ca.pem")
	if err != nil {
		panic(err)
	}
	if !certPool.AppendCertsFromPEM(rootBuf) {
		panic("Fail to append ca")
	}

	tlsConf := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
	}

	// 开启服务端监听
	listener, err := net.Listen("tcp", "127.0.0.1:8000")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
	qkms_proto.RegisterQkmsServer(server, &qkms_server)

	reflection.Register(server)

	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
