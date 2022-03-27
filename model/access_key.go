package qkms_model

type AccessKey struct {
	ID           uint64 `gorm:"primaryKey;column:id"`
	NameSpace    string `gorm:"index:idx_ak,unique;column:namespace"`
	Name         string `gorm:"index:idx_ak,unique;column:name"`
	CipherTextAK string `gorm:"column:ciphertextak"`
	KeyType      string `gorm:"column:keytype"`
	Srand        uint64 `gorm:"column:srand"`
	TimeStamp    uint64 `gorm:"column:timestamp"`
	Environment  string `gorm:"column:environment"`
	Version      uint64 `gorm:"column:version"`
	KEKVersion   uint64 `gorm:"column:kekversion"`
	OwnerAppkey  string `gorm:"column:ownerappkey"`
}

func (AccessKey) TableName() string {
	return "AccessKeys"
}
