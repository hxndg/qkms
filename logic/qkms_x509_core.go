package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_crypto "qkms/crypto"

	"github.com/golang/glog"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

/* only allow root now */
func (server *QkmsRealServer) GenerateUsertCertInternal(ctx context.Context, organization string, country string, province string, locality string, name string, key_type string) (*string, *string, error) {
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
	appkey := qkms_crypto.Base64Encoding(qkms_crypto.GeneratePass(40))
	commonname := fmt.Sprintf("user=%s,appkey=%s", name, appkey)
	cert, key, err := server.GenerateCert(ctx, organization, country, province, locality, commonname, key_type)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
