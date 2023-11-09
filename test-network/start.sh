export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
./network.sh up createChannel
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go -ccl go



