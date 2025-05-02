package qkms_model

type User struct {
	ID            uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	Name          string `gorm:"column:name"`
	AppKey        string `gorm:"index:idx_user,unique;column:appkey"`
	Cert          string `gorm:"column:cert"`
	KeyCipherText string `gorm:"column:keyciphertext"`
	KeyType       string `gorm:"column:keytype"`
	Srand         uint64 `gorm:"column:srand;type:numeric"`
	TimeStamp     uint64 `gorm:"column:timestamp;type:numeric"`
	Version       uint64 `gorm:"column:version;type:numeric"`
	KEK           string `gorm:"column:kek"`
}

func (User) TableName() string {
	return "Users"
}
