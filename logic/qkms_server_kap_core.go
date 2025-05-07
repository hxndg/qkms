package qkms_logic

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	qkms_dal "qkms/dal"

	"github.com/golang/glog"
	ast "github.com/open-policy-agent/opa/v1/ast"
	rego "github.com/open-policy-agent/opa/v1/rego"
)

func (server *QkmsRealServer) LoadKAP() error {
	policys, _ := qkms_dal.GetDal().AccquireAllKAR(context.Background())
	regoCode, err := GenerateRegoPolicy(*policys)
	if err != nil {
		glog.Error(fmt.Sprintf("GenerateRegoPolicy failed, error: %s", err.Error()))
		return err
	}
	glog.Info(*regoCode)

	newHash := fmt.Sprintf("%x", sha256.Sum256([]byte(*regoCode)))
	if newHash == server.opa.lastHash {
		return nil
	}

	compiler, err := ast.CompileModules(map[string]string{
		"authz.rego": *regoCode,
	})
	if err != nil {
		glog.Error(fmt.Sprintf("CompileModules failed, rego policy str is %+v, error: %s", *regoCode, err.Error()))
		return err
	}
	ctx := context.TODO()
	query, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.authz.allow"),
	).PrepareForEval(ctx)

	if err != nil {
		glog.Error(fmt.Sprintf("PrepareForEval failed, rego policy str is %+v, error: %s", *regoCode, err.Error()))
		return err
	}

	server.opa.policyMu.Lock()
	defer server.opa.policyMu.Unlock()

	server.opa.preparedQuery = query
	server.opa.lastHash = newHash

	return nil
}

func (server *QkmsRealServer) IsKAPLoaded() bool {
	return server.opa.lastHash != ""
}

func (server *QkmsRealServer) ResetKAPHash() {
	server.opa.lastHash = ""
}

func (server *QkmsRealServer) CheckKAP(ctx context.Context, namespace string, key_name string, environment string, user string, action string) (bool, error) {
	server.opa.policyMu.RLock()
	defer server.opa.policyMu.RUnlock()

	if !server.IsKAPLoaded() {
		return false, errors.New("policy not loaded")
	}

	input := map[string]interface{}{
		"environment": environment,
		"user":        user,
		"namespace":   namespace,
		"key":         key_name,
		"action":      action,
	}

	result, err := server.opa.preparedQuery.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		glog.Error(fmt.Sprintf("Eval failed, error: %s", err.Error()))
		return false, err
	}

	if len(result) == 0 || len(result[0].Expressions) == 0 {
		glog.Error(fmt.Sprintf("Eval failed, error: %s", "no result"))
		return false, errors.New("no result")
	}

	allowed, ok := result[0].Expressions[0].Value.(bool)
	if !ok {
		return false, errors.New("invalid policy result")
	}

	return allowed, nil
}

func (server *QkmsRealServer) CreateOrUpdateKeyAuthorizationPolicyInternal(ctx context.Context, namespace string, name string, environment string, userappkey string, action string, effect string) (uint64, error) {
	_, err := qkms_dal.GetDal().CreateOrUpdateKeyAuthorizationPolicy(ctx, namespace, name, environment, userappkey, action, effect)
	if err != nil {
		glog.Error(fmt.Sprintf("CreateOrUpdateKeyAuthorizationPolicy failed, namespace = %s AND keyname = %s AND environment = %s AND userappkey = %s AND grantedappkey = %s And operationtype = %s And effect = %s", namespace, name, environment, userappkey, action, effect, err.Error()))
		return 0, err
	}
	return 0, nil
}
