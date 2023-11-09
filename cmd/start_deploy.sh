# 部署自定义的链码
../test-network/network.sh up createChannel

../test-network/network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go -ccl go