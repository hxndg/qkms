package qkms_logic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_proto "qkms/proto"

	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/golang/glog"
	cmap "github.com/orcaman/concurrent-map"
)

type QkmsRealServer struct {
	qkms_proto.UnimplementedQkmsServer
	x509_cert tls.Certificate
	root_key  []byte
	cache_key []byte
	ak_map    cmap.ConcurrentMap
	kek_map   cmap.ConcurrentMap
	kar_map   cmap.ConcurrentMap
	adapter   *pgadapter.Adapter
	enforcer  *casbin.Enforcer
}

func (server *QkmsRealServer) Init(cert string, key string, db_config qkms_dal.DBConfig, rbac string) error {
	qkms_dal.MustInit(db_config)
	var err error
	server.x509_cert, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load Cert & Key")
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
	server.ak_map = cmap.New()
	server.kek_map = cmap.New()
	server.kar_map = cmap.New()
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
		panic(err)
	}
	if len(users) == 0 {
		var default_root string
		fmt.Printf("Please enter default root")
		fmt.Scanf("%s", &default_root)
		grant, err := server.GrantRoleForUserInternal(context.Background(), default_root, "root")
		if err != nil || !grant {
			glog.Error("Create default root failed, user appkey", default_root)
			panic(err)
		}
	}
	return nil
}
