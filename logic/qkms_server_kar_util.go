package qkms_logic

import (
	"errors"
	qkms_common "qkms/common"

	cmap "github.com/orcaman/concurrent-map"
)

type CacheKAR struct {
	NameSpace         string
	Name              string
	Environment       string
	OwnerAppkey       string
	ReadbleAppkeys    cmap.ConcurrentMap
	WritableAppkeys   cmap.ConcurrentMap
	UnReadbleAppkeys  cmap.ConcurrentMap
	UnWritableAppkeys cmap.ConcurrentMap
}

// 内存中的KEK存储在concurrentmap当中
// key为Namespace#Environment，value为EncryptedCacheKEK
func CheckBehaviorValid(behavior string) error {
	if behavior != "read" && behavior != "write" {
		return errors.New("invalid behavior")
	}
	return nil
}

func (kar *CacheKAR) CheckCacheKARBehavior(appkey string, behavior string) (uint64, error) {
	if behavior == "read" {
		if _, ok := kar.ReadbleAppkeys.Get(appkey); ok {
			return qkms_common.QKMS_ERROR_CODE_READ_VALID, nil
		}
		if _, ok := kar.UnReadbleAppkeys.Get(appkey); ok {
			return qkms_common.QKMS_ERROR_CODE_READ_INVALID, errors.New("invalid read behavior")
		}
	}

	if behavior == "write" {
		if _, ok := kar.WritableAppkeys.Get(appkey); ok {
			return qkms_common.QKMS_ERROR_CODE_WRITE_VALID, nil
		}
		if _, ok := kar.UnWritableAppkeys.Get(appkey); ok {
			return qkms_common.QKMS_ERROR_CODE_WRITE_INVALID, errors.New("invalid write behavior")
		}
	}
	return qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN, nil
}

func (kar *CacheKAR) UpdateCacheKARBehavior(appkey string, behavior string, allow bool) (uint64, error) {
	if behavior == "read" {
		if allow {
			kar.ReadbleAppkeys.SetIfAbsent(appkey, true)
			kar.UnReadbleAppkeys.Remove(appkey)
		} else {
			kar.UnReadbleAppkeys.SetIfAbsent(appkey, true)
			kar.ReadbleAppkeys.Remove(appkey)
		}
	}

	if behavior == "write" {
		if allow {
			kar.WritableAppkeys.SetIfAbsent(appkey, true)
			kar.UnWritableAppkeys.Remove(appkey)
		} else {
			kar.UnWritableAppkeys.SetIfAbsent(appkey, true)
			kar.WritableAppkeys.Remove(appkey)
		}
	}
	return qkms_common.QKMS_ERROR_CODE_CACHE_KAR_UPDATE, nil
}
