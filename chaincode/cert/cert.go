package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
)

// SmartContract provides functions for managing an user
type SmartContract struct {
	contractapi.Contract
}

// Cert 证书
type Cert struct {
	CertId    string `json:"certId"`    // 证书ID
	Version   int    `json:"version"`   // 版本
	BeginDate string `json:"beginDate"` // 开始时间
	EndDate   string `json:"endDate"`   // 结束时间
	Subject   string `json:"subject"`   // 使用者名称
	CertHash  string `json:"certHash"`  //证书的HASH
	Sign      string `json:"sign"`      // 证书的签名值
	AccountId string `json:"accountId"` //用户区块链唯一ID 指向用户的Id
}

// MockCert 假数据
var MockCert = Cert{
	CertId:    "-1",
	Version:   3,
	BeginDate: "",
	EndDate:   "",
	Subject:   "",
	CertHash:  "",
	Sign:      "",
	AccountId: "",
}

// 初始化账本

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	certJson, err := json.Marshal(MockCert)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(MockCert.CertId, certJson)
	return err
}

// 添加证书

func (s *SmartContract) AddCert(ctx contractapi.TransactionContextInterface, id string, certJson []byte) error {
	err := ctx.GetStub().PutState(id, certJson)
	return err
}

// 删除证书

func (s *SmartContract) DeleteCert(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.CertExist(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the cert %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

//  返回用户与给定ID存在世界的状态

func (s *SmartContract) CertExist(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	certJson, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return certJson != nil, nil
}

// 获取所有的证书

func (s *SmartContract) GetAllCerts(ctx contractapi.TransactionContextInterface) ([]*Cert, error) {
	// GetStateByRange 查询参数为两个空字符串时即查询所有数据
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var certs []*Cert
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert Cert
		err = json.Unmarshal(queryResponse.Value, &cert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, &cert)
	}

	return certs, nil
}

func main() {
	userChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err := userChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
}
