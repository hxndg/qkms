package qkms_model

type KeyEncryptKey struct {
	ID           uint64 `gorm:"primaryKey;column:id"`
	NameSpace    string `gorm:"index;column:namespace"`
	EncryptedKEK string `gorm:"column:encrypted_kek"`
	KeyType      string `gorm:"column:key_type"`
	Srand        uint64 `gorm:"column:srand"`
	TimeStamp    uint64 `gorm:"column:timestamp"`
	Environment  string `gorm:"column:environment"`
	Version      uint64 `gorm:"column:version"`
	RKVersion    uint64 `gorm:"column:rk_version"`
	OwnerAppkey  string `gorm:"column:appkey"`
}
