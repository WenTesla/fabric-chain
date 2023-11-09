package gateway

const (
	channel       = "channel"
	chaincodeName = "cert"
)

// 初始化一个链接

var CertContract = InitConfigContract(channel, chaincodeName)
