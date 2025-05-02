package qkms_crypto

import (
	crypto_rand "crypto/rand"
	"math/big"
	math_rand "math/rand"
	"time"

	"github.com/golang/glog"
)

func GenerateSrandAndTimeStamp() (uint64, uint64) {
	math_rand.Seed(time.Now().Unix())
	return math_rand.Uint64(), uint64(time.Now().Unix())
}

func GenerateRandomBigInt() (*big.Int, error) {
	//generate random serialnumber
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	serial_number, err := crypto_rand.Int(crypto_rand.Reader, max)
	if err != nil {
		return nil, err
	}
	glog.Info("create new seriable number:", serial_number)

	return serial_number, nil
}
