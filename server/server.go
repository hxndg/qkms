package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	qkms_dal "qkms/dal"
	qkms_logic "qkms/logic"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	flag.Parse()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config/")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w ", err))
	}
	db_config := qkms_dal.DBConfig{
		DbName:   viper.GetString("DB_CONFIG.DB_NAME"),
		Host:     viper.GetString("DB_CONFIG.DB_HOST"),
		Port:     viper.GetInt("DB_CONFIG.DB_PORT"),
		Username: viper.GetString("DB_CONFIG.DB_USERNAME"),
		Password: viper.GetString("DB_CONFIG.DB_PASSWORD"),
	}

	var qkms_server qkms_logic.QkmsRealServer
	err = qkms_server.Init(viper.GetString("SERVER_CERT_PATH"), viper.GetString("SERVER_KEY_PATH"), db_config, "config/rbac_model.conf")
	if err != nil {
		glog.Error("Can't Init QkmsRealServer for", err.Error())
		panic(err)
	} else {
		glog.Error("QkmsRealServer init")
	}

	cert, err := tls.LoadX509KeyPair(viper.GetString("SERVER_CERT_PATH"), viper.GetString("SERVER_KEY_PATH"))
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	rootBuf, err := ioutil.ReadFile(viper.GetString("CA_CERT_PATH"))
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
	} else {
		glog.Error("QkmsRealServer start listen")
	}
}
