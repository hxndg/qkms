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
	regoCode := GenerateRegoPolicy(*policys)
	newHash := fmt.Sprintf("%x", sha256.Sum256([]byte(regoCode)))
	glog.Info(regoCode)
	if newHash == server.opa.lastHash {
		return nil
	}
	compiler, err := ast.CompileModules(map[string]string{
		"authz.rego": regoCode,
	})
	if err != nil {
		return err
	}
	ctx := context.TODO()
	query, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.authz.allow"),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare query failed: %w", err)
	}

	server.opa.policyMu.Lock()
	defer server.opa.policyMu.Unlock()
	server.opa.preparedQuery = query
	server.opa.lastHash = newHash
	return nil
}

func (server *QkmsRealServer) CheckKAP(ctx context.Context, namespace string, name string, environment string, ownerappkey string, grantedappkey string, behavior string) (bool, error) {
	server.opa.policyMu.RLock()
	defer server.opa.policyMu.RUnlock()

	if server.opa.lastHash == "" {
		return false, errors.New("policy not loaded")
	}

	input := map[string]interface{}{
		"environment": environment,
		"user":        ownerappkey,
		"namespace":   namespace,
		"key":         name,
		"action":      behavior,
	}

	result, err := server.opa.preparedQuery.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("evaluation error: %w", err)
	}

	if len(result) == 0 || len(result[0].Expressions) == 0 {
		return false, nil
	}

	allowed, ok := result[0].Expressions[0].Value.(bool)
	if !ok {
		return false, errors.New("invalid policy result")
	}

	return allowed, nil
}

func (server *QkmsRealServer) GrantKAPInternal(ctx context.Context, namespace string, name string, environment string, userappkey string, action string, effect string) (uint64, error) {

	_, err := qkms_dal.GetDal().FetchOrCreateKeyAuthorizationPolicy(ctx, namespace, name, environment, userappkey, action, effect)
	if err != nil {
		glog.Error(fmt.Sprintf("FetchOrCreateKeyAuthorizationPolicy failed, namespace = %s AND keyname = %s AND environment = %s AND userappkey = %s AND grantedappkey = %s And operationtype = %s And effect = %s", namespace, name, environment, userappkey, action, effect, err.Error()))
		return 0, err
	}
	return 0, nil
}
