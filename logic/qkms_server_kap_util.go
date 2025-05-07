package qkms_logic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	qkms_model "qkms/model"
	"text/template"

	"github.com/golang/glog"
)

type GlobalLevelPolicy struct {
	Name        string              `json:"name"`
	Action2User map[string][]string `json:"action2user"`
}

type EnvironmentLevelPolicy struct {
	Name            string                         `json:"name"`
	Env2Action2User map[string]map[string][]string `json:"env2action2user"`
}

type NameSpaceLevelPolicy struct {
	Name               string                                    `json:"name"`
	Env2NS2Action2User map[string]map[string]map[string][]string `json:"env2ns2action2user"`
}

type KeyNameLevelPolicy struct {
	Name                  string                                               `json:"name"`
	Env2NS2Key2ActionUser map[string]map[string]map[string]map[string][]string `json:"env2ns2key2action2user"`
}

func GenerateRegoPolicy(rules []qkms_model.KeyAuthorizationPolicy) (*string, error) {

	// action -> users
	global_policies := GlobalLevelPolicy{
		Name:        "global_policies",
		Action2User: make(map[string][]string),
	}
	// env -> action ->users
	environment_policies := EnvironmentLevelPolicy{
		Name:            "environment_policies",
		Env2Action2User: make(map[string]map[string][]string),
	}
	// env -> ns -> action -> users
	namespace_policies := NameSpaceLevelPolicy{
		Name:               "namespace_policies",
		Env2NS2Action2User: make(map[string]map[string]map[string][]string),
	}

	// env -> ns -> key -> action -> users
	key_policies := KeyNameLevelPolicy{
		Name:                  "key_policies",
		Env2NS2Key2ActionUser: make(map[string]map[string]map[string]map[string][]string),
	}

	for _, rule := range rules {
		if rule.Effect != "allow" {
			continue
		}

		env := rule.Environment
		ns := rule.NameSpace
		kn := rule.KeyName
		ot := rule.OperationType
		user := rule.UserAppkey
		if env == "*" && ns == "*" && kn == "*" {
			if global_policies.Action2User[ot] == nil {
				global_policies.Action2User[ot] = []string{user}
			} else {
				global_policies.Action2User[ot] = append(global_policies.Action2User[ot], user)
			}
			continue
		}

		// 全局规则, only when namespace & keyname both *
		if env != "*" && ns == "*" && kn == "*" {
			if environment_policies.Env2Action2User[env] == nil {
				environment_policies.Env2Action2User[env] = make(map[string][]string)
			}
			if environment_policies.Env2Action2User[env][ot] == nil {
				environment_policies.Env2Action2User[env][ot] = []string{user}
			} else {
				environment_policies.Env2Action2User[env][ot] = append(global_policies.Action2User[ot], user)
			}
			continue
		}

		// 命名空间级规则
		if env != "*" && ns != "*" && kn == "*" {
			if namespace_policies.Env2NS2Action2User[env] == nil {
				namespace_policies.Env2NS2Action2User[env] = make(map[string]map[string][]string)
			}
			if namespace_policies.Env2NS2Action2User[env][ns] == nil {
				namespace_policies.Env2NS2Action2User[env][ns] = make(map[string][]string)
			}
			if namespace_policies.Env2NS2Action2User[env][ns][ot] == nil {
				namespace_policies.Env2NS2Action2User[env][ns][ot] = []string{user}
			} else {
				namespace_policies.Env2NS2Action2User[env][ns][ot] = append(namespace_policies.Env2NS2Action2User[env][ns][ot], user)

			}
			continue
		}

		// 键级规则
		if env != "*" && ns != "*" && kn != "*" {
			if key_policies.Env2NS2Key2ActionUser[env] == nil {
				key_policies.Env2NS2Key2ActionUser[env] = make(map[string]map[string]map[string][]string)
			}
			if key_policies.Env2NS2Key2ActionUser[env][ns] == nil {
				key_policies.Env2NS2Key2ActionUser[env][ns] = make(map[string]map[string][]string)
			}
			if key_policies.Env2NS2Key2ActionUser[env][ns][kn] == nil {
				key_policies.Env2NS2Key2ActionUser[env][ns][kn] = make(map[string][]string)
			}
			if key_policies.Env2NS2Key2ActionUser[env][ns][kn][ot] == nil {
				key_policies.Env2NS2Key2ActionUser[env][ns][kn][ot] = []string{user}
			} else {
				key_policies.Env2NS2Key2ActionUser[env][ns][kn][ot] = append(key_policies.Env2NS2Key2ActionUser[env][ns][kn][ot], user)
			}
			continue
		}
		// we don't allow namespace be * and keyname not *
	}

	global_policies_json, err := json.MarshalIndent(global_policies.Action2User, "", "  ")
	if err != nil {
		glog.Error(fmt.Sprintf("Marsh global_policies json failed, global_policies is %+v, error is %s", global_policies, err.Error()))
		return nil, err
	}

	environment_policies_json, err := json.MarshalIndent(environment_policies.Env2Action2User, "", "  ")
	if err != nil {
		glog.Error(fmt.Sprintf("Marsh environment_policies json failed, environment_policies is %+v, error is %s", environment_policies, err.Error()))
		return nil, err
	}

	namespace_policies_json, err := json.MarshalIndent(namespace_policies.Env2NS2Action2User, "", "  ")
	if err != nil {
		glog.Error(fmt.Sprintf("Marsh namespace_policies json failed, namespace_policies is %+v, error is %s", namespace_policies, err.Error()))
		return nil, err
	}

	key_policies_json, err := json.MarshalIndent(key_policies.Env2NS2Key2ActionUser, "", "  ")
	if err != nil {
		glog.Error(fmt.Sprintf("Marsh key_policies json failed, key_policies is %+v, error is %s", key_policies, err.Error()))
		return nil, err
	}

	tmplStr := `package authz

default allow = false

# global policy, allow environment & namespace & name both *
allow if {
    global_policies[input.action][_] = input.user
}

# environment policy, environment can't be * !
allow if {
    environment_policies[input.environment][input.action][_] == input.user
}

# namespace policy
allow if {
    namespace_policies[input.environment][input.namespace][input.action][_] == input.user
}

# key policy
allow if {
    key_policies[input.environment][input.namespace][input.key][input.action][_] == input.user
}

{{.GlobalPolicies}} := {{.GlobalPoliciesJSON}}

{{.EnvironmentPolicies}} := {{.EnvironmentPoliciesJSON}}

{{.NameSpacePolicies}} := {{.NameSpacePoliciesJSON}}

{{.KeyPolicies}} := {{.KeyPoliciesJSON}}`

	tmpl, err := template.New("RegoEngine").Parse(tmplStr)
	if err != nil {
		glog.Error(fmt.Sprintf("template parse error, template is %+v, error is %s", tmplStr, err.Error()))
		return nil, err
	}

	// 准备传递给模板的数据
	data := struct {
		GlobalPolicies          string
		GlobalPoliciesJSON      string
		EnvironmentPolicies     string
		EnvironmentPoliciesJSON string
		NameSpacePolicies       string
		NameSpacePoliciesJSON   string
		KeyPolicies             string
		KeyPoliciesJSON         string
	}{
		GlobalPolicies:          global_policies.Name,
		GlobalPoliciesJSON:      string(global_policies_json),
		EnvironmentPolicies:     environment_policies.Name,
		EnvironmentPoliciesJSON: string(environment_policies_json),
		NameSpacePolicies:       namespace_policies.Name,
		NameSpacePoliciesJSON:   string(namespace_policies_json),
		KeyPolicies:             key_policies.Name,
		KeyPoliciesJSON:         string(key_policies_json),
	}

	var repoPolicyBytes bytes.Buffer

	err = tmpl.Execute(&repoPolicyBytes, data)
	if err != nil {
		glog.Error(fmt.Sprintf("template execute error, template is %+v, input data is %+v, error is %s", tmplStr, data, err.Error()))
		return nil, err
	}

	repoPolicyString := repoPolicyBytes.String()
	glog.Error(fmt.Sprintf("generate rego policy success, policy is %+v", repoPolicyString))

	return &repoPolicyString, nil
}

func CheckBehaviorValid(action string) error {
	if action != "read" && action != "write" {
		return errors.New("invalid action")
	}
	return nil
}
