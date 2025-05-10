package qkms_dal

import (
	"context"
	"encoding/json"
	"fmt"
	qkms_model "qkms/model"
	"regexp"

	"github.com/golang/glog"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func (d *Dal) CreateAccessKey(ctx context.Context, key *qkms_model.AccessKey) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容
		if err := tx.Create(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Create AK failed!, AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}

		// 返回 nil 提交事务
		glog.Info(fmt.Sprintf("Create AK success!, AK Info :%+v", *key))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) UpdateAccessKey(ctx context.Context, key *qkms_model.AccessKey) (uint64, error) {
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容，先读取旧的ak
		var old_ak qkms_model.AccessKey
		if err := tx.Model(&qkms_model.AccessKey{}).Where("namespace = ? AND name = ? AND keytype = ? AND environment = ? AND version = ? AND ownerappkey = ?", key.NameSpace, key.Name, key.KeyType, key.Environment, key.Version-1, key.OwnerAppkey).First(&old_ak).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, Can't find original AK! AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}
		if err := tx.Model(&old_ak).Updates(key).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, AK Info :%+v, Failed info: %s", *key, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Update AK success!, AK Info :%+v", *key))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) AccquireAccessKey(ctx context.Context, namespace string, name string, environment string) (*qkms_model.AccessKey, error) {
	var ak qkms_model.AccessKey
	result := d.Query(ctx).Where("namespace = ? AND name = ? AND environment = ?", namespace, name, environment).First(&ak)
	if result.Error != nil {
		glog.Error(fmt.Sprintf("Accquire AK failed!, Namespace: %s, Name: %s, Environment: %s, Failed Info: %s", namespace, name, environment, result.Error.Error()))
		return nil, result.Error
	}
	glog.Info(fmt.Sprintf("Accquire AK success!, AK Info :%+v", ak))
	return &ak, nil
}

func isValid(s string) bool {
	// ^[a-zA-Z0-9_]+$ 表示只允许字母、数字、下划线，且不能为空
	match, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, s)
	return match
}

func isTagKeyValid(s string) bool {
	return isValid(s) && len(s) <= 1024
}

func isTagValueValid(s string) bool {
	return isValid(s) && len(s) <= 1024
}

func (d *Dal) AccquireAccessKeyByTags(ctx context.Context, namespace string, name string, environment string, conditions map[string]string) (*[]qkms_model.AccessKey, error) {
	// 1. 参数校验
	for key, value := range conditions {
		if !(isTagKeyValid(key) && isTagValueValid(value)) {
			glog.Error(fmt.Sprintf("tag character unsupported, key: %s, value: %s", key, value))
			return nil, fmt.Errorf("tag character unsupported, key: %s, value: %s", key, value)
		}
	}

	// 2. 构建安全查询条件

	query := d.Query(ctx).Model(&qkms_model.AccessKey{})
	if namespace != "" {
		query = query.Where("namespace = ?", namespace)
	}
	if name != "" {
		query = query.Where("name = ?", name)
	}
	if environment != "" {
		query = query.Where("environment = ?", environment)
	}

	for key, value := range conditions {
		jsonPath := fmt.Sprintf("attributes->'tags'->>'%s'", key)
		query = query.Where(jsonPath+" = ?", value)
	}
	glog.Error(fmt.Sprintf("######################Accquire AK by tag, tags %+v, namespace %s, name %s, environment %s", conditions, namespace, name, environment))
	var keys []qkms_model.AccessKey
	if err := query.Find(&keys).Error; err != nil {
		glog.Error(fmt.Sprintf("Accquire AK by tag failed!, tags %+v, namespace %s, name %s, environment %s, Failed Info: %s", conditions, namespace, name, environment, err.Error()))
		return nil, err
	}

	glog.Info(fmt.Sprintf("Accquire AK success!, AK Info :%+v", keys))
	return &keys, nil

}

func (d *Dal) GetAccessKeyIndex(ctx context.Context, namespace string) (*[]qkms_model.AccessKey, error) {
	var aks []qkms_model.AccessKey
	if len(namespace) != 0 {
		_ = d.Query(ctx).Where("namespace = ?", namespace).Find(&aks)
	} else {
		_ = d.Query(ctx).Find(&aks)
	}
	return &aks, nil
}

type KeyAttributes struct {
	Tags map[string]string `json:"tags"`
	raw  map[string]json.RawMessage
}

func (c *KeyAttributes) UnmarshalJSON(bytes []byte) error {
	if err := json.Unmarshal(bytes, &c.raw); err != nil {
		return err
	}
	if tags, ok := c.raw["tags"]; ok {
		if err := json.Unmarshal(tags, &c.Tags); err != nil {
			return err
		}
	}
	return nil
}

func (c *KeyAttributes) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(c.Tags)
	if err != nil {
		return nil, err
	}
	c.raw["tags"] = json.RawMessage(bytes)
	return json.Marshal(c.raw)
}

func (d *Dal) TagAccessKey(ctx context.Context, namespace string, name string, environment string, tag_key string, tag_value string) (uint64, error) {
	if !(isTagKeyValid(tag_key) && isTagValueValid(tag_value)) {
		glog.Error(fmt.Sprintf("tag character unsupported, key: %s, value: %s", tag_key, tag_value))
		return 500, fmt.Errorf("tag character unsupported, key: %s, value: %s", tag_key, tag_value)
	}
	trans_error := d.Query(ctx).Transaction(func(tx *gorm.DB) error {
		// 因为我们现在kek新建，所以可以不需要使用共享锁锁住kek
		// 现在尝试写入ak的内容，先读取旧的ak
		var old_ak qkms_model.AccessKey
		if err := tx.Model(&qkms_model.AccessKey{}).Where("namespace = ? AND name = ? AND environment = ?", namespace, name, environment).First(&old_ak).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, Can't find original AK! namespace %s, name %s, environment %s, Failed info: %s", namespace, name, environment, err.Error()))
			return err
		}

		var attrs KeyAttributes
		if err := json.Unmarshal(old_ak.Attributes, &attrs); err != nil {
			glog.Error(fmt.Sprintf("failed to unmarshal ak attributes: %v", err))
			return fmt.Errorf("解析属性失败: %v", err)
		}

		if attrs.Tags == nil {
			attrs.Tags = make(map[string]string)
		}
		attrs.Tags[tag_key] = tag_value

		newData, err := json.Marshal(attrs)
		if err != nil {
			return err
		}

		new_ak := qkms_model.AccessKey{
			NameSpace:      old_ak.NameSpace,
			Name:           old_ak.Name,
			AKCiphertext:   old_ak.AKCiphertext,
			KeyType:        old_ak.KeyType,
			Srand:          old_ak.Srand,
			TimeStamp:      old_ak.TimeStamp,
			Environment:    old_ak.Environment,
			Version:        old_ak.Version,
			KEK:            old_ak.KEK,
			OwnerAppkey:    old_ak.OwnerAppkey,
			LifeTime:       old_ak.LifeTime,
			RotateDuration: old_ak.RotateDuration,
			Attributes:     datatypes.JSON(newData),
		}

		if err := tx.Model(&old_ak).Updates(&new_ak).Error; err != nil {
			glog.Error(fmt.Sprintf("Update AK failed, AK Info :%+v, Failed info: %s", new_ak, err.Error()))
			return err
		}

		glog.Info(fmt.Sprintf("Update AK success!, AK Info :%+v", new_ak))
		return nil
	})
	if trans_error != nil {
		return 500, trans_error
	}
	return 200, nil
}

func (d *Dal) GetAutoRotateAccessKeys(ctx context.Context) (*[]qkms_model.AccessKey, error) {
	var aks []qkms_model.AccessKey
	_ = d.Query(ctx).Not("rotateduration = ?", 0).Find(&aks)

	return &aks, nil
}
