package qkms_model

type KeyEncryptionKey struct {
	ID            uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	Name          string `gorm:"index:idx_kek,unique;column:name"`
	KEKCiphertext string `gorm:"column:kekciphertext"`
	KeyType       string `gorm:"column:keytype"`
	Srand         uint64 `gorm:"column:srand;type:numeric"`
	TimeStamp     uint64 `gorm:"column:timestamp;type:numeric"`
	Environment   string `gorm:"index:idx_kek,unique;column:environment"`
	RK            string `gorm:"column:rk"`
	OwnerAppkey   string `gorm:"column:ownerappkey"`
}

func (KeyEncryptionKey) TableName() string {
	return "KeyEncryptionKeys"
}
