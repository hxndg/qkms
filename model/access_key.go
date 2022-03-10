package qkms_model

type AccessKey struct {
	ID          uint64 `gorm:"primaryKey;column:id"`
	NameSpace   string `gorm:"index;column:namespace"`
	Name        string `gorm:"index;column:name"`
	EncryptedAK string `gorm:"column:encrypted_ak"`
	KeyType     string `gorm:"column:key_type"`
	Srand       uint64 `gorm:"column:srand"`
	TimeStamp   uint64 `gorm:"column:timestamp"`
	Environment string `gorm:"column:environment"`
	Version     uint64 `gorm:"column:version"`
	KEKVersion  uint64 `gorm:"column:kek_version"`
	OwnerAppkey string `gorm:"column:appkey"`
}
