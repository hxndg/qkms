package qkms_model

type KeyAuthorizationPolicy struct {
	ID            uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	UserAppkey    string `gorm:"index:idx_kar;column:userappkey"`
	NameSpace     string `gorm:"index:idx_kar;column:namespace"`
	KeyName       string `gorm:"index:idx_kar;column:keyname"`
	Environment   string `gorm:"index:idx_kar;column:environment"`
	OperationType string `gorm:"index:idx_kar;column:operationtype"`
	Effect        string `gorm:"column:effect"`
}

func (KeyAuthorizationPolicy) TableName() string {
	return "KeyAuthorizationPolicy"
}
