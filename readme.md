# 基于联盟链的PKI证书系统设计与实现

## 环境
Docker  
Go  

## 手动部署
环境要求： 安装了 Docker 和 Docker Compose 的 Linux 或 Mac OS 环境

附 Linux Docker 安装教程：点此跳转

🤔 Docker 和 Docker Compose 需要先自行学习。本项目的区块链网络搭建、链码部署、前后端编译/部署都是使用 Docker 和 Docker Compose 完成的。

项目还未完成！

用户部分基本完成


# 开始部署

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

此后，会在8080端口开放服务器

## 完全清除环境(销毁环境) 
注意，该操作会将所有数据清空。  
```bash
cd test-network

chmod 777 ./network.sh

./network.sh down
```

## 参考文献   
基于区块链（Hyperledger Fabric）的房地产交易系统（可作为区块链毕设项目参考）
https://github.com/togettoyou/fabric-realty  



