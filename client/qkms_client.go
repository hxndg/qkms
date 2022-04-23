package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	qkms_proto "qkms/proto"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {

	// 加载客户端私钥和证书
	cert, err := tls.LoadX509KeyPair("credentials/client/client.pem", "credentials/client/client.key")
	if err != nil {
		panic(err)
	}

	// 将根证书加入证书池
	certPool := x509.NewCertPool()
	rootBuf, err := ioutil.ReadFile("credentials/ca.pem")
	if err != nil {
		panic(err)
	}
	if !certPool.AppendCertsFromPEM(rootBuf) {
		panic("Fail to append ca")
	}

	creds := credentials.NewTLS(&tls.Config{
		ServerName:   "bigdogserver.com",
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	})

	conn, err := grpc.Dial("127.0.0.1:8000", grpc.WithTransportCredentials(creds))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	qkms_client := qkms_proto.NewQkmsClient(conn)
	/*
		create_kek_req := qkms_proto.CreateKeyEncryptionKeyRequest{
			NameSpace:   "kek",
			Environment: "test",
		}
		_, err = qkms_client.CreateKeyEncryptionKey(context.Background(), &create_kek_req)
		if err != nil {
			glog.Error("Creat kek failed!, err :%s", err.Error())
			os.Exit(1)

		}
		create_ak_req := qkms_proto.CreateAccessKeyRequest{
			NameSpace:   "kek",
			Name:        "new_ak",
			AKPlaintext: qkms_crypto.Base64Encoding([]byte("u got be joke")),
			KeyType:     "opaque",
			Environment: "test",
		}
		_, err = qkms_client.CreateAccessKey(context.Background(), &create_ak_req)
		if err != nil {
			glog.Error("Creat AK failed, err:%s", err.Error())
			os.Exit(1)
		}

		read_ak_req := qkms_proto.ReadAccessKeyRequest{
			NameSpace:   "kek",
			Name:        "new_ak",
			Environment: "test",
		}
		read_ak_reply, err := qkms_client.ReadAccessKey(context.Background(), &read_ak_req)
		if err != nil {
			glog.Error("Read AK failed!, err: %s", err.Error())
		} else {
			ak_plaintext, err := qkms_crypto.Base64Decoding(read_ak_reply.AKPlaintext)
			if err != nil {
				glog.Error("Decode base64 failed")
			} else {
				glog.Info(fmt.Sprintf("Read AK success! Namespace:%s, Name:%s, KeyType:%s, Environment:%s, AKPlainText:%s", read_ak_reply.NameSpace, read_ak_reply.Name, read_ak_reply.KeyType, read_ak_reply.Environment, ak_plaintext))
			}
		}
	*/
	gen_credential_req := qkms_proto.GenerateCredentialRequest{
		Name: "hxndg",
	}
	gen_credential_reply, err := qkms_client.GenerateCredential(context.Background(), &gen_credential_req)
	if err != nil {
		glog.Error("Generate credential failed!, err: %s", err.Error())
		panic(err)
	}
	glog.Info("result:", gen_credential_reply.String())

}
