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
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_proto "qkms/proto"
	"time"

	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
	cmap "github.com/orcaman/concurrent-map"
)

type QkmsRealServer struct {
	qkms_proto.UnimplementedQkmsServer
	credential    tls.Certificate
	ca_credential tls.Certificate
	ca_cert       *x509.Certificate
	crl           *pkix.CertificateList
	root_key      []byte
	cache_key     []byte
	ak_map        cmap.ConcurrentMap
	kek_map       cmap.ConcurrentMap
	kar_map       cmap.ConcurrentMap
	adapter       *pgadapter.Adapter
	enforcer      *casbin.Enforcer
}

func getPrivateKey(priv interface{}) crypto.Signer {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		glog.Error("get private key return rsa")
		return k
	case *ecdsa.PrivateKey:
		glog.Error("get private key return ecdsa")
		return k
	default:
		glog.Error("get private key return nil")
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

func (server *QkmsRealServer) InitServerCrl() error {

	template := &x509.RevocationList{
		Number: big.NewInt(42),
	}
	raw_crl_bytes, err := x509.CreateRevocationList(rand.Reader, template, server.ca_cert, getPrivateKey(server.ca_credential.PrivateKey))
	if err != nil {
		panic(err)
	}

	server.crl, err = x509.ParseCRL(raw_crl_bytes)
	if err != nil {
		glog.Error("Crl invalid, can't parse")
		return err
	}
	err = server.ca_cert.CheckCRLSignature(server.crl)
	if err != nil {
		glog.Error("Crl invalid, can't verify")
		return err
	}
	if server.crl.TBSCertList.NextUpdate.Before(time.Now()) {
		glog.Error("Crl invalid, need update can't verify")
		return errors.New("crl need update")
	}
	revoke_certs, err := qkms_dal.GetDal().AccquireRevokeCerts(context.Background())
	if err != nil {
		glog.Error("Can't lod revoke certs, err: %s", err.Error())
	} else {
		for _, cert := range *revoke_certs {
			serial_number := new(big.Int)
			serial_number, ok := serial_number.SetString(cert.SerialNumber, 10)
			if !ok {
				glog.Error("Transfer string to big int failed")
				continue
			}
			revoke_cert := pkix.RevokedCertificate{
				SerialNumber:   serial_number,
				RevocationTime: time.Now(),
			}
			glog.Info("Crl append cert serialnumber:", cert.SerialNumber)
			server.crl.TBSCertList.RevokedCertificates = append(server.crl.TBSCertList.RevokedCertificates, revoke_cert)
		}
	}
	return nil
}

func (server *QkmsRealServer) InitServerCredentials(cert string, key string, ca_cert string, ca_key string, crl_file string) error {
	var err error
	server.credential, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load Cert & Key")
		return err
	}
	server.ca_credential, err = tls.LoadX509KeyPair(ca_cert, ca_key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load CA Cert & Key")
		return err
	}
	server.ca_cert, err = x509.ParseCertificate(server.ca_credential.Certificate[0])
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't extract x509 format cert")
		return err
	}
	x509_key, err := x509.MarshalPKCS8PrivateKey(server.credential.PrivateKey)
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

	/* no user kek, create one */
	_, _, err = server.ReadKEKByNamespace(context.Background(), "user", "production")
	if err != nil {
		_, err = server.CreateKEKInternal(context.Background(), "user", "production")
		if err != nil {
			glog.Error("Init QKMS Server Failed! Can't generate user namespace kek")
			return err
		}
	}
	err = server.InitServerCrl()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't generate crl")
		return err
	}
	return nil
}

func (server *QkmsRealServer) InitServerRBAC(db_config qkms_dal.DBConfig, rbac string) error {
	var err error
	opts, _ := pg.ParseURL(fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable",
		db_config.Username, db_config.Password, db_config.Host, db_config.Port, db_config.DbName,
	))

	db := pg.Connect(opts)
	defer db.Close()

	server.adapter, err = pgadapter.NewAdapterByDB(db, pgadapter.WithTableName("rbac_table"))
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
		var name string
		fmt.Printf("Please enter default root user name:\n")
		fmt.Scanf("%s", &name)
		plain_root_credential, err := server.GenerateCredentialInternal(context.Background(), server.ca_cert.Issuer.Organization[0], server.ca_cert.Issuer.Country[0], server.ca_cert.Issuer.Province[0], server.ca_cert.Issuer.Locality[0], name, "rsa_4096")
		if err != nil {
			glog.Error("Create default root failed, user name:", name)
			return err
		}
		grant, err := server.GrantRoleForUserInternal(context.Background(), plain_root_credential.AppKey, "root")
		if err != nil || !grant {
			glog.Error("Create default root failed, user appkey:", plain_root_credential.AppKey)
			return err
		}
		glog.Info("Please record root user's credentials")
		glog.Info("Name:", plain_root_credential.Name)
		glog.Info("AppKey:", plain_root_credential.AppKey)
		glog.Info("Cert:\n", plain_root_credential.Cert)
		glog.Info("Key:\n", plain_root_credential.KeyPlaintext)
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

	err := server.InitServerCmap()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Concurrent map")
		return err
	}

	err = server.InitServerCredentials(cert, key, ca_cert, ca_key, crl_file)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Credentials")
		return err
	}

	err = server.InitServerRBAC(db_config, rbac)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server RBAC")
		return err
	}

	return nil
}
