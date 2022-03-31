package qkms_model

type KeyAuthorizationRelation struct {
	ID            uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	NameSpace     string `gorm:"index:idx_kar,unique;column:namespace"`
	Name          string `gorm:"index:idx_kar,unique;column:name"`
	Environment   string `gorm:"column:environment"`
	OwnerAppkey   string `gorm:"column:ownerappkey"`
	GrantedAppkey string `gorm:"column:grantappkey"`
	Behavior      string `gorm:"column:behavior"`
}

func (KeyAuthorizationRelation) TableName() string {
	return "KeyAuthorizationRelations"
}
