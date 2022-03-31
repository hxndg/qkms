package qkms_logic

import (
	"context"
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
func CheckOperationValid(operation string) error {
	if operation != "read" || operation != "write" {
		return errors.New("invalid operation")
	}
	return nil
}

func (kar *CacheKAR) CheckReadValid(appkey string) (uint64, error) {
	if _, ok := kar.ReadbleAppkeys.Get(appkey); ok {
		return qkms_common.QKMS_ERROR_CODE_READ_VALID, nil
	}
	if _, ok := kar.UnReadbleAppkeys.Get(appkey); ok {
		return qkms_common.QKMS_ERROR_CODE_READ_INVALID, errors.New("invalid read operation")
	}
	return qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN, nil
}

func (kar *CacheKAR) CheckWriteValid(appkey string) (uint64, error) {
	if _, ok := kar.WritableAppkeys.Get(appkey); ok {
		return qkms_common.QKMS_ERROR_CODE_READ_VALID, nil
	}
	if _, ok := kar.UnWritableAppkeys.Get(appkey); ok {
		return qkms_common.QKMS_ERROR_CODE_READ_INVALID, errors.New("invalid write operation")
	}
	return qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN, nil
}

func (server *QkmsRealServer) CheckOperationValid(ctx context.Context, namespace string, name string, environment string, appkey string, operation string) (uint64, error) {
	err := CheckOperationValid(operation)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_INVALID_OPERATION, errors.New("invalid operation")
	}
	cmap_key := namespace + "#" + name + "#" + environment
	if check, ok := server.kar_map.Get(cmap_key); ok {
		cache_kar := check.(CacheKAR)
		if operation == "read" {
			error_code, err := (&cache_kar).CheckReadValid(appkey)
			if error_code != qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN {
				return error_code, err
			}
		} else {
			error_code, err := (&cache_kar).CheckWriteValid(appkey)
			if error_code != qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN {
				return error_code, err
			}
		}
	}

}
