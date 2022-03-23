package qkms_logic

import (
	"crypto/tls"
	"crypto/x509"
	qkms_crypto "qkms/crypto"
	pb "qkms/proto"

	"github.com/golang/glog"
	cmap "github.com/orcaman/concurrent-map"
)

type QkmsRealServer struct {
	pb.UnimplementedQkmsServer
	x509_cert tls.Certificate
	root_key  []byte
	cache_key []byte
	ak_map    cmap.ConcurrentMap
	kek_map   cmap.ConcurrentMap
}

func (server *QkmsRealServer) Init(cert string, key string) error {
	var err error
	server.x509_cert, err = tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load Cert & Key")
		return err
	}
	x509_key, err := x509.MarshalPKCS8PrivateKey(server.x509_cert.PrivateKey)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't x509.MarshalPKCS8PrivateKey Key")
		return err
	}

	root_key_info := qkms_crypto.GenerateIV(32)
	server.root_key, err = qkms_crypto.Sha256HKDF(x509_key, root_key_info, 16)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't qkms_crypto.Sha256HKDF Server Root Key")
		return err
	}

	cache_key_info := qkms_crypto.GenerateIV(32)
	server.cache_key, err = qkms_crypto.Sha256HKDF(x509_key, cache_key_info, 16)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't qkms_crypto.Sha256HKDF Server Root Key")
		return err
	}
	server.ak_map = cmap.New()
	server.kek_map = cmap.New()
	return nil
}
