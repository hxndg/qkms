package qkms_logic

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_proto "qkms/proto"
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/v1/rego"
	cmap "github.com/orcaman/concurrent-map"
)

type OPAManager struct {
	preparedQuery rego.PreparedEvalQuery
	policyMu      sync.RWMutex
	lastHash      string
}

type QkmsRealServer struct {
	qkms_proto.UnimplementedQkmsServer
	credential         tls.Certificate
	ca_credential      tls.Certificate
	ca_cert            *x509.Certificate
	crl                *pkix.CertificateList
	root_key           []byte
	cache_key          []byte
	ak_map             cmap.ConcurrentMap
	kek_map            cmap.ConcurrentMap
	kar_map            cmap.ConcurrentMap
	cipher_key_len_map cmap.ConcurrentMap
	scheduler          *gocron.Scheduler
	opa                *OPAManager
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

func (server *QkmsRealServer) InitScheduler() error {
	server.scheduler = gocron.NewScheduler(time.UTC)
	server.scheduler.StartAsync()

	rotate_aks, err := qkms_dal.GetDal().GetAutoRotateAccessKeys(context.Background())
	if err != nil {
		glog.Error("Get rotate aks failed: ", err.Error())
		return err
	}
	for _, rotate_ak := range *rotate_aks {
		glog.Info("Register rotate AK: %+v ", rotate_ak)
		_, err := server.scheduler.Every(int(rotate_ak.RotateDuration)).Tag(rotate_ak.NameSpace + "-" + rotate_ak.Environment + "-" + rotate_ak.Name).Do(func() {
			err := server.RotateAccessKeyInternal(rotate_ak.NameSpace, rotate_ak.Name, rotate_ak.KeyType, rotate_ak.Environment)
			if err != nil {
				glog.Error("Rotate AK failed: ", err.Error())
			}
		})
		if err != nil {
			glog.Error("Schedule Rotate AK failed: ", err.Error())
		}
	}
	glog.Error("Schedule Rotate AK success, let's go")
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
	// if server.crl.TBSCertList.NextUpdate.Before(time.Now()) {
	// 	glog.Error("Crl invalid, need update can't verify")
	// 	glog.Error("crl need update time: ", server.crl.TBSCertList.NextUpdate)
	// 	glog.Error("crl this update time: ", server.crl.TBSCertList.ThisUpdate)
	// 	glog.Error("current time: ", time.Now())
	// 	return errors.New("crl need update")
	// }
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

func (server *QkmsRealServer) InitServerCredentials(cert string, key string, ca_cert string, ca_key string) error {
	var err error
	server.credential, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load Cert & Key")
		return err
	}
	server.ca_credential, err = tls.LoadX509KeyPair(ca_cert, ca_key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Load CA Cert: ", ca_cert, ",   Key:", ca_key)
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

	err = server.InitServerCrl()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't generate crl")
		return err
	}

	return nil
}

func (server *QkmsRealServer) InitServerAdministrator() error {
	admins, err := server.GetAdminsInternal(context.Background())
	if err != nil {
		glog.Error(fmt.Sprintf("GetAdmin failed, error: %s", err.Error()))
		return err
	}
	if len(*admins) == 0 {
		var name, key_type string
		fmt.Printf("Please enter default root user name:\n")
		fmt.Scanf("%s", &name)
		fmt.Printf("Use default root key type rsa_4096:\n")
		// here we generate a root user with default name and appkey
		// but it depends on production user table, so generate first and insert later
		plain_root_credential, err := server.GenerateCredentialOnly(context.Background(), server.ca_cert.Issuer.Organization[0], server.ca_cert.Issuer.Country[0], server.ca_cert.Issuer.Province[0], server.ca_cert.Issuer.Locality[0], name, "rsa_4096", 0, "unknown")
		if err != nil {
			glog.Error(fmt.Sprintf(
				"Create default root failed, user name:%s, key_type:%s",
				name, key_type))

			return err
		}

		glog.Error("Please record root user's credentials")
		glog.Error("Name:", plain_root_credential.Name)
		glog.Error("AppKey:", plain_root_credential.AppKey)
		glog.Error("\nCert:\n", plain_root_credential.Cert)
		glog.Error("\nKey:\n", plain_root_credential.KeyPlaintext)

		/* if no user kek, create one */
		_, user_table_kek, err := server.ReadKEKByNamespace(context.Background(), "user", "production")
		if err != nil {
			user_table_kek, err = server.CreateNameSpaceInternal(context.Background(), "user", "production", plain_root_credential.AppKey)
			if err != nil {
				glog.Error("Init QKMS Server Failed! Can't generate user namespace kek")
				return err
			}
		}

		plain_root_credential.KEK = user_table_kek.Name
		_, err = server.InsertCacheUser2DB(context.Background(), plain_root_credential)
		if err != nil {
			glog.Error("Init QKMS Server Failed! Can't insert root creadential namespace")
			return err
		}

		// grant admin and update kap
		server.GrantAdminInternal(context.Background(), plain_root_credential.AppKey)
		server.CreateOrUpdateKeyAuthorizationPolicyInternal(context.Background(), "*", "*", "*", plain_root_credential.AppKey, "read", "allow")
		server.CreateOrUpdateKeyAuthorizationPolicyInternal(context.Background(), "*", "*", "*", plain_root_credential.AppKey, "write", "allow")

		// every kap updated, we need to load it
		if err := server.LoadKAP(); err != nil {
			glog.Error(fmt.Sprintf("LoadKAP failed, error: %s", err.Error()))
		}
	}
	return nil
}

func (server *QkmsRealServer) InitServerCmap() error {
	server.ak_map = cmap.New()
	server.kek_map = cmap.New()
	server.kar_map = cmap.New()
	server.cipher_key_len_map = cmap.New()
	server.cipher_key_len_map.Set("AES-CTR-128", 16)
	server.cipher_key_len_map.Set("AES-CTR-256", 32)
	server.cipher_key_len_map.Set("AES-CTR-512", 64)
	server.cipher_key_len_map.Set("RSA-2048", 256)
	server.cipher_key_len_map.Set("RSA-4096", 512)
	return nil
}

func (server *QkmsRealServer) InitOpa() error {
	server.opa = &OPAManager{
		policyMu:      sync.RWMutex{},
		preparedQuery: rego.PreparedEvalQuery{},
		lastHash:      "",
	}
	return nil
}

func (server *QkmsRealServer) Init(cert string, key string, ca_cert string, ca_key string, db_config qkms_dal.DBConfig, rbac string) error {
	qkms_dal.MustInit(db_config)

	err := server.InitServerCmap()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Concurrent map")
		return err
	}

	err = server.InitServerCredentials(cert, key, ca_cert, ca_key)
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server Credentials")
		return err
	}

	_ = server.InitOpa()

	err = server.InitServerAdministrator()
	if err != nil {
		glog.Error("Init QKMS Server Failed! Can't Init Server admin")
		return err
	}
	_ = server.InitScheduler()
	if err := server.LoadKAP(); err != nil {
		glog.Error(fmt.Sprintf("LoadKAP failed, error: %s", err.Error()))
	}
	return nil
}
