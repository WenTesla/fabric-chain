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

type Users struct {
	// Id
	ID string `json:"Id"`
	// 姓名
	Name string `json:"name"`
	// 密码
	Password string `json:"password"`
	// 邮箱
	Email string `json:"email"`
	// 是否管理员
	IsAdmin int `json:"isAdmin"`
	//// 创建时间
	CreateTime string `json:"createTime"`
	//// 修改时间
	UpdateTime string `json:"updateTime"`
	// RSA 公钥 base64编码
	PublicKey string `json:"publicKey"`
	//// RSA 私钥
	//SecretKey string `json:"secretKey"`
	// 证书Id
	CertId string `json:"certId"`
}

//  初始化账本

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	var users = []Users{
		{ID: "1", Name: "bowen", Password: "123456"},
		{ID: "2", Name: "admin", Password: "123456"},
		{ID: "3", Name: "test", Password: "123456"}}
	for _, user := range users {
		userJSON, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = ctx.GetStub().PutState(user.ID, userJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}
	return nil
}

//  创建用户

func (s *SmartContract) CreateUser(ctx contractapi.TransactionContextInterface, id, name, password, email, createTime, publicKey string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the user %s already exists", id)
	}
	user := Users{
		ID:         id,
		Name:       name,
		Password:   password,
		Email:      email,
		IsAdmin:    0,
		CreateTime: createTime,
		UpdateTime: createTime,
		PublicKey:  publicKey,
		//SecretKey:  secretKey,
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

//  读入用户

func (s *SmartContract) ReadUser(ctx contractapi.TransactionContextInterface, id string) (*Users, error) {
	userJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if userJSON == nil {
		return nil, fmt.Errorf("the user %s does not exist", id)
	}
	var user Users
	err = json.Unmarshal(userJSON, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// 添加证书的Id到用户

func (s *SmartContract) AddCertIdToUser(ctx contractapi.TransactionContextInterface, id string, certId string) error {
	user, err := s.ReadUser(ctx, id)
	if err != nil {
		return err
	}
	user.CertId = certId
	// 添加
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

//  返回用户与给定ID存在世界的状态

func (s *SmartContract) UserExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	userJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return userJSON != nil, nil
}

// 删除用户

func (s *SmartContract) DeleteUser(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the user %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

// 根据主键更新

func (s *SmartContract) UpdateUser(ctx contractapi.TransactionContextInterface, id string, password string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the user %s does not exist", id)
	}

	// overwriting original user with new user
	user := Users{ID: id, Password: password}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	println(user)
	return ctx.GetStub().PutState(id, userJSON)
}

// 获取所有用户

func (s *SmartContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]*Users, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all users in the chaincode namespace.
	// GetStateByRange 查询参数为两个空字符串时即查询所有数据
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var users []*Users
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var user Users
		err = json.Unmarshal(queryResponse.Value, &user)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	return users, nil
}

// 修改某个用户的密码

func (s *SmartContract) UpdatePassword(ctx contractapi.TransactionContextInterface, id, password string) error {
	exist, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("user is not exist: %v", err)
	}
	user, err := s.ReadUser(ctx, id)
	if err != nil {
		return err
	}
	user.Password = password
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
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
