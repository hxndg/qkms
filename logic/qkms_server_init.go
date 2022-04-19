package qkms_logic

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_proto "qkms/proto"
	"time"

	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/golang/glog"
	cmap "github.com/orcaman/concurrent-map"
)

type QkmsRealServer struct {
	qkms_proto.UnimplementedQkmsServer
	x509_cert    tls.Certificate
	x509_ca_cert tls.Certificate
	crl          *pkix.CertificateList
	root_key     []byte
	cache_key    []byte
	ak_map       cmap.ConcurrentMap
	kek_map      cmap.ConcurrentMap
	kar_map      cmap.ConcurrentMap
	adapter      *pgadapter.Adapter
	enforcer     *casbin.Enforcer
}

func getPrivateKey(priv interface{}) crypto.Signer {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k
	case *ecdsa.PrivateKey:
		return k
	default:
		return nil
	}
}

func (server *QkmsRealServer) CleanServer(crl_file string) error {
	crl_pem := &pem.Block{
		Type:    "X509 CRL",
		Headers: nil,
		Bytes:   server.crl.TBSCertList.Raw,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, crl_pem); err != nil {
		glog.Error("Pem transfer crl pem fail")
		panic(err)
	}
	err := ioutil.WriteFile(crl_file, buf.Bytes(), 0644)
	if err != nil {
		glog.Error("Pem encode crl pem fail")
		panic(err)
	}
	return nil
}

func (server *QkmsRealServer) InitServerCredentials(cert string, key string, ca_cert string, ca_key string, crl_file string) error {
	var err error
	server.x509_cert, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load Cert & Key")
		return err
	}
	server.x509_ca_cert, err = tls.LoadX509KeyPair(ca_cert, ca_key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load CA Cert & Key")
		return err
	}

	x509_key, err := x509.MarshalPKCS8PrivateKey(server.x509_cert.PrivateKey)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't x509.MarshalPKCS8PrivateKey Key")
		return err
	}

	server.root_key, err = qkms_crypto.Sha256HKDF(x509_key, x509_key, 16)
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

	_, err = server.CreateKEKInternal(context.Background(), "user", "production")
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't generate user namespace kek")
		return err
	}

	_, err = os.Stat(crl_file)
	var raw_crl *[]byte
	if os.IsNotExist(err) {
		template := &x509.RevocationList{
			Number: big.NewInt(42),
		}
		*raw_crl, err = x509.CreateRevocationList(rand.Reader, template, server.x509_ca_cert.Leaf, getPrivateKey(server.x509_ca_cert.PrivateKey))
		if err != nil {
			panic(err)
		}
	} else {
		*raw_crl, err = ioutil.ReadFile(crl_file)
		if err != nil {
			glog.Error("Crl invalid, can't read cry file")
			return err
		}
		block, _ := pem.Decode(*raw_crl)
		if block != nil {
			raw_crl = &block.Bytes
		}
	}

	defer server.CleanServer(crl_file)

	server.crl, err = x509.ParseCRL(*raw_crl)
	if err != nil {
		glog.Error("Crl invalid, can't verify")
		return err
	}
	err = server.x509_ca_cert.Leaf.CheckCRLSignature(server.crl)
	if err != nil {
		glog.Error("Crl invalid, can't verify")
		return err
	}
	if server.crl.TBSCertList.NextUpdate.Before(time.Now()) {
		glog.Error("Crl invalid, need update can't verify")
		return errors.New("crl need update")
	}

	return nil
}

func (server *QkmsRealServer) InitServerRBAC(db_config qkms_dal.DBConfig, rbac string) error {
	var err error
	server.adapter, err = pgadapter.NewAdapter(fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable",
		db_config.Username, db_config.Password, db_config.Host, db_config.Port, db_config.DbName,
	))
	if err != nil {
		glog.Error("Casbin can't connect to postgresql", err.Error())
		return err
	}
	server.enforcer, err = casbin.NewEnforcer(rbac, server.adapter)
	if err != nil {
		glog.Error("Can't create enforcer", err.Error())
		return err
	}
	server.enforcer.LoadPolicy()
	// if root role empty, will ask for one
	users, err := server.enforcer.GetUsersForRole("root")
	if err != nil {
		return err
	}
	if len(users) == 0 {
		var default_root string
		fmt.Printf("Please enter default root appkey")
		fmt.Scanf("%s", &default_root)
		grant, err := server.GrantRoleForUserInternal(context.Background(), default_root, "root")
		if err != nil || !grant {
			glog.Error("Create default root failed, user appkey", default_root)
			return err
		}
	}
	return nil
}

func (server *QkmsRealServer) InitServerCmap() error {
	server.ak_map = cmap.New()
	server.kek_map = cmap.New()
	server.kar_map = cmap.New()
	return nil
}

func (server *QkmsRealServer) Init(cert string, key string, ca_cert string, ca_key string, crl_file string, db_config qkms_dal.DBConfig, rbac string) error {
	qkms_dal.MustInit(db_config)

	err := server.InitServerCredentials(cert, key, ca_cert, ca_key, crl_file)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Credentials")
		return err
	}

	err = server.InitServerRBAC(db_config, rbac)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server RBAC")
		return err
	}

	err = server.InitServerCmap()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Concurrent map")
		return err
	}

	return nil
}
