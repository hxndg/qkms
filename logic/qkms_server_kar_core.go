package qkms_logic

import (
	"context"
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"

	"github.com/golang/glog"
	cmap "github.com/orcaman/concurrent-map"
)

func (server *QkmsRealServer) CheckKAR(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (uint64, error) {
	err := CheckBehaviorValid(behavior)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_INVALID_OPERATION, errors.New("invalid behavior")
	}

	if ownerappkey == grantedappkey {
		return qkms_common.QKMS_ERROR_CODE_KAR_FIND, nil
	}
	cmap_key := namespace + "#" + name + "#" + environment
	var cache_kar *CacheKAR
	if check, ok := server.kar_map.Get(cmap_key); ok {
		cache_kar = check.(*CacheKAR)
		error_code, err := cache_kar.CheckCacheKARBehavior(grantedappkey, behavior)
		if error_code != qkms_common.QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN {
			glog.Info(fmt.Sprintf("Check Cache KAR Not Exist! Namespace:%s, Name:%s,Environment:%s", namespace, name, environment))
			return error_code, err
		}
	} else {
		cache_kar = &CacheKAR{
			NameSpace:         namespace,
			Name:              name,
			Environment:       environment,
			OwnerAppkey:       ownerappkey,
			ReadbleAppkeys:    cmap.New(),
			WritableAppkeys:   cmap.New(),
			UnReadbleAppkeys:  cmap.New(),
			UnWritableAppkeys: cmap.New(),
		}
	}
	_, err = qkms_dal.GetDal().CheckKeyAuthorizationRelation(ctx, namespace, name, environment, ownerappkey, grantedappkey, behavior)
	cache_kar.UpdateCacheKARBehavior(grantedappkey, behavior, err == nil)
	server.kar_map.SetIfAbsent(cmap_key, cache_kar)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_KAR_NOT_FIND, err
	}
	return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, errors.New("internal error")
}

func (server *QkmsRealServer) GrantKARInternal(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (uint64, error) {
	err := CheckBehaviorValid(behavior)
	if err != nil {
		return qkms_common.QKMS_ERROR_CODE_INVALID_OPERATION, errors.New("invalid behavior")
	}

	if ownerappkey == grantedappkey {
		return qkms_common.QKMS_ERROR_CODE_KAR_GRANTED, nil
	}
	cmap_key := namespace + "#" + name + "#" + environment
	var cache_kar *CacheKAR
	if check, ok := server.kar_map.Get(cmap_key); ok {
		cache_kar = check.(*CacheKAR)
		//修正，这里如果先改了read，就不能再赋值write了
		error_code, _ := cache_kar.CheckCacheKARBehavior(grantedappkey, behavior)
		if (behavior == read && error_code == qkms_common.QKMS_ERROR_CODE_READ_VALID)
		if  || error_code == qkms_common.QKMS_ERROR_CODE_WRITE_VALID {
			return qkms_common.QKMS_ERROR_CODE_KAR_GRANTED, nil
		}
	} else {
		cache_kar = &CacheKAR{
			NameSpace:         namespace,
			Name:              name,
			Environment:       environment,
			OwnerAppkey:       ownerappkey,
			ReadbleAppkeys:    cmap.New(),
			WritableAppkeys:   cmap.New(),
			UnReadbleAppkeys:  cmap.New(),
			UnWritableAppkeys: cmap.New(),
		}
		server.kar_map.Set(cmap_key, cache_kar)
	}
	add_kar := &qkms_model.KeyAuthorizationRelation{
		NameSpace:     namespace,
		Name:          name,
		Environment:   environment,
		OwnerAppkey:   ownerappkey,
		GrantedAppkey: grantedappkey,
		Behavior:      behavior,
	}
	_, err = qkms_dal.GetDal().CreateKeyAuthorizationRelation(ctx, add_kar)

	cache_kar.UpdateCacheKARBehavior(grantedappkey, behavior, err == nil)
	if err == nil {
		return qkms_common.QKMS_ERROR_CODE_KAR_GRANTED, nil
	}

	return qkms_common.QKMS_ERROR_CODE_INTERNAL_ERROR, errors.New("internal error")
}
