package qkms_model

type AccessKey struct {
	ID          uint64 `gorm:"primaryKey;column:id"`
	NameSpace   string `gorm:"uniqueIndex;column:namespace"`
	Name        string `gorm:"uniqueIndex;column:name"`
	EncryptedAK string `gorm:"column:encryptedak"`
	KeyType     string `gorm:"column:keytype"`
	Srand       uint64 `gorm:"column:srand"`
	TimeStamp   uint64 `gorm:"column:timestamp"`
	Environment string `gorm:"column:environment"`
	Version     uint64 `gorm:"column:version"`
	KEKVersion  uint64 `gorm:"column:kekversion"`
	OwnerAppkey string `gorm:"column:ownerappkey"`
}

func (AccessKey) TableName() string {
	return "AccessKeys"
}
