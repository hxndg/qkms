package qkms_logic

import (
	"context"
	"fmt"
	qkms_dal "qkms/dal"
	qkms_model "qkms/model"

	"github.com/golang/glog"
)

func (server *QkmsRealServer) CheckPolicyForUserInternal(ctx context.Context, user string, namespace string, behavior string) (bool, error) {
	// for root, allow each behavior
	roles, err := server.enforcer.GetRolesForUser(user)
	if err != nil {
		glog.Info(fmt.Sprintf("check policy failed, user:%s, err:%s", user, err.Error()))
		return false, err
	}
	for _, role := range roles {
		if role == "root" {
			glog.Info(fmt.Sprintf("%s user is root, allow for namespace: %s, behavior: %s", user, namespace, behavior))
			return true, nil
		}
	}

	res, err := server.enforcer.Enforce(user, namespace, behavior)
	if err != nil {
		glog.Info(fmt.Sprintf("check policy failed, user:%s, namespace:%s, behavior:%s, err:%s", user, namespace, behavior, err.Error()))
		return false, err
	}
	return res, nil
}

func (server *QkmsRealServer) CreateRoleInternal(ctx context.Context, name string) error {
	role := &qkms_model.Role{
		Name: name,
	}
	_, err := qkms_dal.GetDal().CreateRole(ctx, role)
	if err != nil {
		glog.Info(fmt.Sprintf("create role failed, role:%s, err:%s", name, err.Error()))
		return err
	}
	return nil
}

func (server *QkmsRealServer) GrantNameSpaceForRoleInternal(ctx context.Context, role string, namespace string, behavior string) error {
	_, err := server.enforcer.AddPolicy(role, namespace, behavior)
	if err != nil {
		glog.Info(fmt.Sprintf("grant role failed, role:%s, namespace:%s, behavior:%s, err : %s", role, namespace, behavior, err.Error()))
		return err
	}
	return nil
}

func (server *QkmsRealServer) GrantRoleForUserInternal(ctx context.Context, user string, role string) (bool, error) {
	grant, err := server.enforcer.AddRoleForUser(user, role)
	if err != nil {
		glog.Error(fmt.Sprintf("AddRoleForUser error, %s", err.Error()))
		return grant, err
	}
	return grant, nil
}
