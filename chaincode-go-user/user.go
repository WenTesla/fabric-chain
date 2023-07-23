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
	ID         string `json:"Id"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	Sex        string `json:"sex"`
	Email      string `json:"email"`
	BirthDay   string `json:"birthDay"`
	County     string `json:"county"`
	CreateTime string `json:"createTime"`
}

// InitLedger 初始化账本
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	var users = []Users{
		{ID: "1", Name: "bowen", Password: "xxx", Sex: "0", Email: "WenTesla@163.com"},
		{ID: "2", Name: "lichangyuan", Password: "xxx"},
		{ID: "3", Name: "test", Password: "xxxxx"}}
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

// CreateUser 创建用户
func (s *SmartContract) CreateUser(ctx contractapi.TransactionContextInterface, id string, name string, password string, sex string, email string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the user %s already exists", id)
	}
	user := Users{ID: id, Name: name, Password: password, Sex: sex, Email: email}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

// ReadUser 读入用户
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

// UserExists returns true when user with given ID exists in world state
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
func (s *SmartContract) UpdateUser(ctx contractapi.TransactionContextInterface, id string, password string, email string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the user %s does not exist", id)
	}

	// overwriting original user with new user
	user := Users{ID: id, Password: password, Email: email}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

// 获取所有用户
func (s *SmartContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]*Users, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all users in the chaincode namespace.
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

// 添加下一个用户
func (s *SmartContract) AddNextUser(ctx contractapi.TransactionContextInterface) error {

	return nil
}
func main() {
	userChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating user-transfer-basic chaincode: %v", err)
	}

	if err := userChaincode.Start(); err != nil {
		log.Panicf("Error starting user-transfer-basic chaincode: %v", err)
	}
}
