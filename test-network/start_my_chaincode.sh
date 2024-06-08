#export PATH=${PWD}/../bin:$PATH
#export FABRIC_CFG_PATH=$PWD/../config/

# 创建网络并启动链码
./network.sh up createChannel


# 开始部署链码 (-cnn 链码名称 -cpp 路径 -ccl 语言)
./network.sh deployCC  -ccn user -ccp ../chaincode/user -ccl go
# 根CA链码
./network.sh deployCC  -ccn RootCA -ccp ../chaincode/CA/RootCA -ccl go
# 中间CA链码
./network.sh deployCC  -ccn MiddleCA -ccp ../chaincode/CA/IntermediateCA -ccl go

# 第二个
#./network.sh up createChannel

#./network.sh deployCC  -ccn CA -ccp ../chaincode/CA -ccl go