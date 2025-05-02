package qkms_logic

// KEKPlaintext是经过base64编码的明文密钥
type NamespaceInfo struct {
	Name        string
	KEK         string
	Environment string
	OwnerAppkey string
}
