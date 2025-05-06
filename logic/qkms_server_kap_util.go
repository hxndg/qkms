package qkms_logic

import (
	"errors"
	"fmt"
	qkms_common "qkms/common"
	qkms_model "qkms/model"
	"strings"

	cmap "github.com/orcaman/concurrent-map"
)

func GenerateRegoPolicy(rules []qkms_model.KeyAuthorizationPolicy) string {
	var sb strings.Builder

	sb.WriteString(`package authz
	
	default allow = false
	
	# global policy, environment can't be * !
	allow {
		users := global_policies[input.environment][input.action]
		users[_] == input.user
	}
	
	# environment+namespace policy
	allow {
	  ns_policies[input.environment][input.namespace][input.action][_] == input.user
	}
	
	# environment+namespace+key policy
	allow {
	  key_policies[input.environment][input.namespace][input.key][input.action][_] == input.user
	}`)

	// 初始化数据结构
	globalPolicies := make(map[string]map[string]map[string]bool)                    // env -> action ->users
	nsPolicies := make(map[string]map[string]map[string]map[string]bool)             // env -> ns -> action -> users
	keyPolicies := make(map[string]map[string]map[string]map[string]map[string]bool) // env -> ns -> key -> action -> users

	for _, rule := range rules {
		if rule.Effect != "allow" {
			continue
		}

		env := rule.Environment
		// Disallow env be *, we don't allow this super user to exist.
		// if env == "" {
		// 	env = "*"
		// }

		// 全局规则, only when namespace & keyname both *
		if rule.NameSpace == "*" && rule.KeyName == "*" {
			if globalPolicies[env] == nil {
				globalPolicies[env] = make(map[string]map[string]bool)
			}
			if globalPolicies[env][rule.OperationType] == nil {
				globalPolicies[env][rule.OperationType] = make(map[string]bool)
			}
			globalPolicies[env][rule.UserAppkey][rule.UserAppkey] = true
			continue
		}

		// 命名空间级规则
		if rule.NameSpace != "*" && rule.KeyName == "*" {
			if nsPolicies[env] == nil {
				nsPolicies[env] = make(map[string]map[string]map[string]bool)
			}
			if nsPolicies[env][rule.NameSpace] == nil {
				nsPolicies[env][rule.NameSpace] = make(map[string]map[string]bool)
			}
			if nsPolicies[env][rule.NameSpace][rule.OperationType] == nil {
				nsPolicies[env][rule.NameSpace][rule.OperationType] = make(map[string]bool)
			}
			nsPolicies[env][rule.NameSpace][rule.OperationType][rule.UserAppkey] = true
			continue
		}

		// 键级规则
		if rule.NameSpace != "*" && rule.KeyName != "*" {
			if keyPolicies[env] == nil {
				keyPolicies[env] = make(map[string]map[string]map[string]map[string]bool)
			}
			if keyPolicies[env][rule.NameSpace] == nil {
				keyPolicies[env][rule.NameSpace] = make(map[string]map[string]map[string]bool)
			}
			if keyPolicies[env][rule.NameSpace][rule.KeyName] == nil {
				keyPolicies[env][rule.NameSpace][rule.KeyName] = make(map[string]map[string]bool)
			}
			if keyPolicies[env][rule.NameSpace][rule.KeyName][rule.OperationType] == nil {
				keyPolicies[env][rule.NameSpace][rule.KeyName][rule.OperationType] = make(map[string]bool)
			}
			keyPolicies[env][rule.NameSpace][rule.KeyName][rule.OperationType][rule.UserAppkey] = true
			continue
		}
		// we don't allow namespace be * and keyname not *

	}

	// 生成全局策略
	sb.WriteString("\nglobal_policies = {\n")
	for env, actions := range globalPolicies {
		sb.WriteString(fmt.Sprintf(`  "%s": {\n`, env))
		for action, users := range actions {
			sb.WriteString(fmt.Sprintf(`"%s": [`, action))
			for u := range users {
				sb.WriteString(fmt.Sprintf(`"%s",`, u))
			}
			sb.WriteString("],")
		}
		sb.WriteString("  },\n")
	}
	sb.WriteString("}\n")

	// 生成命名空间策略
	sb.WriteString("ns_policies = {\n")
	for env, namespaces := range nsPolicies {
		sb.WriteString(fmt.Sprintf(`  "%s": {\n`, env))
		for ns, actions := range namespaces {
			sb.WriteString(fmt.Sprintf(`    "%s": {`, ns))
			for action, users := range actions {
				sb.WriteString(fmt.Sprintf(`"%s": [`, action))
				for u := range users {
					sb.WriteString(fmt.Sprintf(`"%s",`, u))
				}
				sb.WriteString("],")
			}
			sb.WriteString("},\n")
		}
		sb.WriteString("  },\n")
	}
	sb.WriteString("}\n")

	// 生成键级策略
	sb.WriteString("key_policies = {\n")
	for env, namespaces := range keyPolicies {
		sb.WriteString(fmt.Sprintf(`  "%s": {\n`, env))
		for ns, keys := range namespaces {
			sb.WriteString(fmt.Sprintf(`    "%s": {\n`, ns))
			for key, actions := range keys {
				sb.WriteString(fmt.Sprintf(`      "%s": {`, key))
				for action, users := range actions {
					sb.WriteString(fmt.Sprintf(`"%s": [`, action))
					for u := range users {
						sb.WriteString(fmt.Sprintf(`"%s",`, u))
					}
					sb.WriteString("],")
				}
				sb.WriteString("},\n")
			}
			sb.WriteString("    },\n")
		}
		sb.WriteString("  },\n")
	}
	sb.WriteString("}\n")

	return sb.String()
}

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
