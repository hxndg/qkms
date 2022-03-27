package qkms_crypto

import (
	"math/rand"
	"time"
)

func GetSrandAndTimeStamp() (uint64, uint64) {
	rand.Seed(time.Now().Unix())
	return rand.Uint64(), uint64(time.Now().Unix())
}
