package qkms_logic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	qkms_crypto "qkms/crypto"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type PlainCacheUser struct {
	Name         string
	AppKey       string
	Cert         string
	KeyPlaintext string
	KeyType      string
	Version      uint64
	KEKVersion   uint64
}

type CipherCacheUser struct {
	Name         string
	AppKey       string
	Cert         string
	KeyPlaintext string
	KeyType      string
	Version      uint64
	KEKVersion   uint64
}

func PlainCacheUser2ModelUser(in *PlainCacheUser, key []byte) (*qkms_model.User, error) {
	out := qkms_model.User{
		Name:       in.Name,
		AppKey:     in.AppKey,
		Cert:       in.Cert,
		KeyType:    in.KeyType,
		Version:    in.Version,
		KEKVersion: in.KEKVersion,
	}
	out.Srand, out.TimeStamp = qkms_crypto.GenerateSrandAndTimeStamp()
	encrypt_iv := qkms_crypto.GenerateIVFromTwoNumber(out.Srand, out.TimeStamp)

	key_plaintext := []byte(in.KeyPlaintext)

	ciphertext_ak, err := qkms_crypto.AesCTREncrypt(key_plaintext, encrypt_iv, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Transfer PlainCache to model.user failed! Can't Encrypt AKPlaintext from %+v, using key %s", *in, qkms_crypto.Base64Encoding(key)))
		return nil, err
	}
	out.KeyCipherText = qkms_crypto.Base64Encoding(ciphertext_ak)
	return &out, nil
}

func getPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func getPemPrivateKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

/* only allow root now */
func (server *QkmsRealServer) GenerateCert(ctx context.Context, organization string, country string, province string, locality string, commonname string, key_type string) (*string, *string, error) {

	serial_number, err := qkms_crypto.GenerateRandomBigInt()
	if err != nil {
		glog.Error("Generate random serial number failed")
		return nil, nil, err
	}
	glog.Info("create new seriable number:", *serial_number)
	cert := &x509.Certificate{
		SerialNumber: serial_number,
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
			Province:     []string{province},
			Locality:     []string{locality},
			CommonName:   commonname,
		},
		NotBefore: time.Now(),
		/* ten yeas cert */
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	var key interface{}
	switch key_type {
	case "ecdsa_521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	/* only allow 4096 rsa bits key */
	case "rsa_4096":
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	}
	if err != nil {
		return nil, nil, err
	}
	cert_bytes, err := x509.CreateCertificate(rand.Reader, cert, server.ca_cert, getPublicKey(key), server.ca_credential.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	cert_out := &bytes.Buffer{}
	pem.Encode(cert_out, &pem.Block{Type: "CERTIFICATE", Bytes: cert_bytes})
	cert_pem := cert_out.String()

	key_out := &bytes.Buffer{}
	pem.Encode(key_out, getPemPrivateKey(key))
	key_pem := key_out.String()
	return &cert_pem, &key_pem, nil
}

func (server *QkmsRealServer) CheckCertRevoked(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		cert := tlsInfo.State.VerifiedChains[0][0]
		for _, revokedCertificate := range server.crl.TBSCertList.RevokedCertificates {
			if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errors.New("cert revoked")
			}
		}
		return nil
	}
	return errors.New("lack cert auth info")
}

func CertToPEM(cert *x509.Certificate) string {
	cert_out := &bytes.Buffer{}
	pem.Encode(cert_out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	cert_pem := cert_out.String()
	return cert_pem
}

func (server *QkmsRealServer) RevokeCert(ctx context.Context, pem_cert string) error {

	block, _ := pem.Decode([]byte(pem_cert))
	if block == nil {
		glog.Error("fail to parse %s", pem_cert)
		return errors.New("can't parse pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	_, err = qkms_dal.GetDal().CreateRevokeCert(ctx, &qkms_model.RevokeCert{
		SerialNumber: cert.SerialNumber.String(),
		Cert:         CertToPEM(cert),
	})
	if err != nil {
		glog.Error(fmt.Sprintf("Create revoke cert failed, cert serial number%s, cert %s", cert.SerialNumber.String(), CertToPEM(cert)))
	}

	revoke_cert := pkix.RevokedCertificate{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	}
	server.crl.TBSCertList.RevokedCertificates = append(server.crl.TBSCertList.RevokedCertificates, revoke_cert)
	glog.Info(fmt.Sprintf("Create revoke cert serial number %s, cert %s", cert.SerialNumber.String(), CertToPEM(cert)))
	return nil

}
