package qkms_model

type RevokeCert struct {
	ID           uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	SerialNumber string `gorm:"column:serialnumber"`
	Cert         string `gorm:"column:cert"`
}

func (RevokeCert) TableName() string {
	return "RevokeCerts"
}
