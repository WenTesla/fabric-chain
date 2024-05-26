# 基于联盟链的PKI证书系统设计与实现

## 环境
- Docker  
- Go  
- Gin
## 主要功能
- 用户注册登录与管理  
- 根CA颁发中间证书
- 中间CA颁发终端证书
- 管理终端证书

## 开始部署

1.部署区块链系统
```bash
cd test-network

chmod 777 ./start_my_chaincode.sh

./start_my_chaincode.sh
```


2.部署web服务器

```bash
cd web 
go run ./main.go

```

此后，会在8080端口开放web服务器

## 完全清除环境(销毁环境) 
注意，该操作会将所有数据清空。  
```bash
cd test-network

chmod 777 ./network.sh

./network.sh down
```
## 项目结构
- bin 官方提供的二进制文件
- chaincode 链码
- config 配置文件
- test-network 部署脚本
- web 服务器（mv架构）

> 此项目的前端的地址 https://github.com/WenTesla/fabric-chain-front

## 参考文献   
基于区块链（Hyperledger Fabric）的房地产交易系统（可作为区块链毕设项目参考）  
https://github.com/togettoyou/fabric-realty  
fabric官方文档  
https://hyperledger-fabric.readthedocs.io/en/release-2.5/whatis.html



