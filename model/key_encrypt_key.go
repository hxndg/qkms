package qkms_model

type KeyEncryptionKey struct {
	ID            uint64 `gorm:"primaryKey;column:id"`
	NameSpace     string `gorm:"index:idx_kek;uniqueIndex;column:namespace"`
	KEKCiphertext string `gorm:"column:kekciphertext"`
	KeyType       string `gorm:"column:keytype"`
	Srand         uint64 `gorm:"column:srand"`
	TimeStamp     uint64 `gorm:"column:timestamp"`
	Environment   string `gorm:"column:environment"`
	Version       uint64 `gorm:"column:version"`
	RKVersion     uint64 `gorm:"column:rkversion"`
	OwnerAppkey   string `gorm:"column:ownerappkey"`
}

func (KeyEncryptionKey) TableName() string {
	return "KeyEncryptionKeys"
}
