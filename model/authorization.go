package qkms_model

type KeyAuthorization struct {
	ID            uint64 `gorm:"primaryKey;column:id"`
	NameSpace     string `gorm:"index;column:namespace"`
	Name          string `gorm:"index;column:name"`
	Environment   string `gorm:"column:environment"`
	GrantedAppkey string `gorm:"column:grant_appkey"`
}
