package qkms_model

type NameSpace struct {
	ID          uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	Name        string `gorm:"index:idx_namespace,unique;column:name"`
	KEK         string `gorm:"column:kek"`
	Environment string `gorm:"index:idx_namespace,unique;column:environment"`
	OwnerAppkey string `gorm:"column:ownerappkey"`
}

func (NameSpace) TableName() string {
	return "NameSpace"
}
