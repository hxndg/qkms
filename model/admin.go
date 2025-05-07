package qkms_model

// root didin't display, it's super user

type Administrator struct {
	ID     uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	AppKey string `gorm:"index:idx_admin,unique;column:appkey"`
}

func (Administrator) TableName() string {
	return "Administrator"
}
