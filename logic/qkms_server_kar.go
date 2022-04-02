package qkms_logic

import (
	"context"
	"errors"
	qkms_common "qkms/common"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"
	qkms_proto "qkms/proto"

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
			return qkms_common.QKMS_ERROR_CODE_READ_VALID, nil
		}
		if _, ok := kar.UnWritableAppkeys.Get(appkey); ok {
			return qkms_common.QKMS_ERROR_CODE_READ_INVALID, errors.New("invalid write behavior")
		}
	}
	return qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN, nil
}

func (kar *CacheKAR) UpdateCacheKARBehavior(appkey string, behavior string, allow bool) (uint64, error) {
	if behavior == "read" {
		if allow {
			kar.ReadbleAppkeys.SetIfAbsent(appkey, true)
		} else {
			kar.UnReadbleAppkeys.SetIfAbsent(appkey, true)
		}
	}

	if behavior == "write" {
		if allow {
			kar.WritableAppkeys.SetIfAbsent(appkey, true)
		} else {
			kar.UnWritableAppkeys.SetIfAbsent(appkey, true)
		}
	}
	return qkms_common.QKMS_ERROR_CODE_CACHE_KAR_UPDATE, nil
}

func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *qkms_proto.GrantAccessKeyAuthorizationRequest) (*qkms_proto.GrantAccessKeyAuthorizationReply, error) {

}

func (server *QkmsRealServer) CheckKARExist(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (uint64, error) {
	err := CheckBehaviorValid(behavior)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_INVALID_OPERATION, errors.New("invalid behavior")
	}
	if ownerappkey == grantedappkey {
		return qkms_common.QKMS_ERROR_CODE_KAR_FIND, nil
	}
	cmap_key := namespace + "#" + name + "#" + environment
	if check, ok := server.kar_map.Get(cmap_key); ok {
		cache_kar := check.(*CacheKAR)
		error_code, err := cache_kar.CheckCacheKARBehavior(grantedappkey, behavior)
		if error_code != qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN {
			return error_code, err
		}
	} else {
		check_kar := qkms_model.KeyAuthorizationRelation{
			NameSpace:     namespace,
			Name:          name,
			Environment:   environment,
			OwnerAppkey:   ownerappkey,
			GrantedAppkey: grantedappkey,
			Behavior:      behavior,
		}
		_, err := qkms_dal.GetDal().CheckKeyAuthorizationRelation(ctx, &check_kar)
		cache_kar := &CacheKAR{
			NameSpace:         namespace,
			Name:              name,
			Environment:       environment,
			OwnerAppkey:       ownerappkey,
			ReadbleAppkeys:    cmap.New(),
			WritableAppkeys:   cmap.New(),
			UnReadbleAppkeys:  cmap.New(),
			UnWritableAppkeys: cmap.New(),
		}
		cache_kar.UpdateCacheKARBehavior(grantedappkey, behavior, err == nil)
		server.kar_map.SetIfAbsent(cmap_key, cache_kar)
		if err != nil {
			return qkms_common.QKMS_ERROR_CODE_KAR_NOT_FIND, err
		}
	}
	return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, errors.New("internal error")
}

func (server *QkmsRealServer) CreateKAR(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (uint64, error) {
	err := CheckBehaviorValid(behavior)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_INVALID_OPERATION, errors.New("invalid behavior")
	}
	if ownerappkey == grantedappkey {
		return qkms_common.QKMS_ERROR_CODE_KAR_FIND, nil
	}
	cmap_key := namespace + "#" + name + "#" + environment
	if check, ok := server.kar_map.Get(cmap_key); ok {
		cache_kar := check.(*CacheKAR)
		error_code, err := cache_kar.CheckCacheKARBehavior(grantedappkey, behavior)
		if error_code != qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN {
			return error_code, err
		}
	} else {
		check_kar := qkms_model.KeyAuthorizationRelation{
			NameSpace:     namespace,
			Name:          name,
			Environment:   environment,
			OwnerAppkey:   ownerappkey,
			GrantedAppkey: grantedappkey,
			Behavior:      behavior,
		}
		_, err := qkms_dal.GetDal().CheckKeyAuthorizationRelation(ctx, &check_kar)
		cache_kar := &CacheKAR{
			NameSpace:         namespace,
			Name:              name,
			Environment:       environment,
			OwnerAppkey:       ownerappkey,
			ReadbleAppkeys:    cmap.New(),
			WritableAppkeys:   cmap.New(),
			UnReadbleAppkeys:  cmap.New(),
			UnWritableAppkeys: cmap.New(),
		}
		cache_kar.UpdateCacheKARBehavior(grantedappkey, behavior, err == nil)
		server.kar_map.SetIfAbsent(cmap_key, cache_kar)
		if err != nil {
			return qkms_common.QKMS_ERROR_CODE_KAR_NOT_FIND, err
		}
	}
	return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, errors.New("internal error")
}
