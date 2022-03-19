package qkms_model

type KeyAuthorizationRelation struct {
	ID            uint64 `gorm:"primaryKey;column:id"`
	NameSpace     string `gorm:"index;column:namespace"`
	Name          string `gorm:"index;column:name"`
	Environment   string `gorm:"column:environment"`
	OwnerAppkey   string `gorm:"column:ownerappkey"`
	GrantedAppkey string `gorm:"column:grantappkey"`
}

func (KeyAuthorizationRelation) TableName() string {
	return "KeyAuthorizationRelations"
}
