package qkms_logic

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	qkms_common "qkms/common"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (server *QkmsRealServer) GenerateUsertCertInternal(ctx context.Context, name string) (*string, *string, error) {
	var ownerappkey *string
	p, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		ownerappkey = Split2GetValue(subject.CommonName, qkms_common.QKMS_CERT_CN_SEP, qkms_common.QKMS_CERT_CN_KV_SEP, qkms_common.QKMS_CERT_CN_APPKEY)
		if ownerappkey == nil {
			glog.Info(fmt.Sprintf("Create KEK failed, received invalid grpc client cert, Client cert subject :%+v, ", subject))
			return nil, nil, errors.New("invalid cert")
		} else {
			glog.Info(fmt.Sprintf("Grpc client plan to create KEK, Client cert subject :%+v", subject))
		}
	}
	allow, err := server.CheckPolicyForUserInternal(ctx, *ownerappkey, "", "")
	if err != nil || !allow {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
}
