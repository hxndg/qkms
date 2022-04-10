package qkms_model

// root didin't display, it's super user

type Role struct {
	ID   uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	Name string `gorm:"index:idx_role,unique;column:name"`
}

func (Role) TableName() string {
	return "Roles"
}
