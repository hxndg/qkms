package qkms_model

type KeyEncryptionKey struct {
	ID            uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	NameSpace     string `gorm:"index:idx_kek,unique;column:namespace"`
	KEKCiphertext string `gorm:"column:kekciphertext"`
	KeyType       string `gorm:"column:keytype"`
	Srand         uint64 `gorm:"column:srand;type:numeric"`
	TimeStamp     uint64 `gorm:"column:timestamp;type:numeric"`
	Environment   string `gorm:"index:idx_kek,unique;column:environment"`
	Version       uint64 `gorm:"column:version;type:numeric"`
	RKVersion     uint64 `gorm:"column:rkversion;type:numeric"`
	OwnerAppkey   string `gorm:"column:ownerappkey"`
}

func (KeyEncryptionKey) TableName() string {
	return "KeyEncryptionKeys"
}
