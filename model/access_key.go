package qkms_model

import (
	"gorm.io/datatypes"
)

type AccessKey struct {
	ID             uint64         `gorm:"primaryKey;column:id;type:bigserial"`
	NameSpace      string         `gorm:"index:idx_ak,unique;column:namespace"`
	Name           string         `gorm:"index:idx_ak,unique;column:name"`
	AKCiphertext   string         `gorm:"column:akciphertext"`
	KeyType        string         `gorm:"column:keytype"`
	Srand          uint64         `gorm:"column:srand;type:numeric"`
	TimeStamp      uint64         `gorm:"column:timestamp;type:numeric"`
	Environment    string         `gorm:"index:idx_ak,unique;column:environment"`
	Version        uint64         `gorm:"column:version;type:numeric"`
	KEK            string         `gorm:"column:kek"`
	OwnerAppkey    string         `gorm:"column:ownerappkey"`
	LifeTime       uint64         `gorm:"column:lifetime;type:numeric"`
	RotateDuration uint64         `gorm:"column:rotateduration;type:numeric"`
	Attributes     datatypes.JSON `gorm:"column:attributes;type:jsonb"`
}

func (AccessKey) TableName() string {
	return "AccessKeys"
}
