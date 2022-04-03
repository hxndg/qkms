package qkms_model

type AccessKey struct {
	ID           uint64 `gorm:"primaryKey;column:id;type:bigserial"`
	NameSpace    string `gorm:"index:idx_ak,unique;column:namespace"`
	Name         string `gorm:"index:idx_ak,unique;column:name"`
	AKCiphertext string `gorm:"column:akciphertext"`
	KeyType      string `gorm:"column:keytype"`
	Srand        uint64 `gorm:"column:srand;type:numeric"`
	TimeStamp    uint64 `gorm:"column:timestamp;type:numeric"`
	Environment  string `gorm:"index:idx_ak,unique;column:environment"`
	Version      uint64 `gorm:"column:version;type:numeric"`
	KEKVersion   uint64 `gorm:"column:kekversion;type:numeric"`
	OwnerAppkey  string `gorm:"column:ownerappkey"`
}

func (AccessKey) TableName() string {
	return "AccessKeys"
}
