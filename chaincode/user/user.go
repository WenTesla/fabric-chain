package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"strconv"
	"time"
)

const (
	rootCA = iota
	inter
)

// SmartContract provides functions for managing an user
type SmartContract struct {
	contractapi.Contract
}

// Users structure used

type Users struct {
	// 唯一Id
	ID string `json:"Id"`
	// 密码
	Password string `json:"password"`
	// 邮箱
	Email string `json:"email"`
	// 是否为CA 0-为普通用户 1-审计用户 2-管理员
	IsCA int `json:"isCA"`
	// 创建时间
	CreateTime string `json:"createTime"`
	// 修改时间
	UpdateTime string `json:"updateTime"`
	// 上次登录时间 时间戳
	LastLoginTime string `json:"lastLoginTime"`
	// RSA 公钥
	PublicKey string `json:"publicKey"`
	// 证书Id
	CertId string `json:"certId"`
	// 状态 0-正常 1-禁用
	Status int `json:"status"`
}

// HistoryQueryResult structure used for returning result of history query
type HistoryQueryResult struct {
	Record    *Users    `json:"user"`
	TxId      string    `json:"txId"`
	Timestamp time.Time `json:"timestamp"`
	IsDelete  bool      `json:"isDelete"`
}

//  初始化账本

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	var users = []Users{
		{ID: "1", Password: "123456"},
		{ID: "2", Password: "123456"},
		{ID: "3", Password: "123456", CreateTime: strconv.FormatInt(timestamp.GetSeconds(), 10)}}
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
	fmt.Println("初始化成功")
	return nil
}

//  创建用户 id password email publicKey

func (s *SmartContract) CreateUser(ctx contractapi.TransactionContextInterface, id, password, email, publicKey string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the user %s already exists", id)
	}
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	user := Users{
		ID:         id,
		Password:   fmt.Sprintf("%x", sha256.Sum256([]byte(password))),
		Email:      email,
		CreateTime: strconv.FormatInt(timestamp.GetSeconds(), 10),
		UpdateTime: strconv.FormatInt(timestamp.GetSeconds(), 10),
		PublicKey:  publicKey,
	}
	// 用户为
	log.Printf("用户为\n%v\n", user)
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

func (s *SmartContract) UpdateUser(ctx contractapi.TransactionContextInterface, id, password, email string) error {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the user %s does not exist", id)
	}
	// overwriting original user with new user
	var user = Users{ID: id, Password: fmt.Sprintf("%x", sha256.Sum256([]byte(password))), Email: email}
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
	user.Password = fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

// 创建CA用户 -Id,Password,email

func (s *SmartContract) CreateCAUser(ctx contractapi.TransactionContextInterface, args ...string) error {
	// 判断是否有重复id
	exist, err := s.UserExists(ctx, args[0])
	if exist {
		return err
	}
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}
	// 创建用户
	user := Users{
		ID:         args[0],
		Password:   fmt.Sprintf("%x", sha256.Sum256([]byte(args[1]))),
		Email:      args[2],
		IsCA:       1,
		CreateTime: strconv.FormatInt(timestamp.GetSeconds(), 10),
		UpdateTime: strconv.FormatInt(timestamp.GetSeconds(), 10),
		PublicKey:  "",
		Status:     0,
	}
	bytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(args[0], bytes)
}

// 根据用户Id禁用用户

func (s *SmartContract) BanUser(ctx contractapi.TransactionContextInterface, id string) error {
	bytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var user Users
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		return err

	}
	user.Status = 1
	bytes, err = json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, bytes)
}

// 根据用户id解禁用户

func (s *SmartContract) UnblockedUser(ctx contractapi.TransactionContextInterface, id string) error {
	bytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var user Users
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		return err

	}
	user.Status = 0
	bytes, err = json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, bytes)
}

// 验证用户密码

func (s *SmartContract) VerifyPassword(ctx contractapi.TransactionContextInterface, id, password string) error {
	user, err := s.ReadUser(ctx, id)
	if err != nil {
		return err
	}
	if user.Status != 0 {
		return fmt.Errorf("用户已被封禁")
	}
	if user.Password != fmt.Sprintf("%x", sha256.Sum256([]byte(password))) {
		return fmt.Errorf("用户密码错误")
	}
	return s.UpdateLoginTime(ctx, id)
}

// 升级用户

func (s *SmartContract) UpgradeUser(ctx contractapi.TransactionContextInterface, id string) error {
	if exists, _ := s.UserExists(ctx, id); !exists {
		return fmt.Errorf("该用户Id:%s不存在", id)
	}
	bytes, _ := ctx.GetStub().GetState(id)
	var user Users
	json.Unmarshal(bytes, &user)
	if user.IsCA < 2 {
		user.IsCA += 1
	}
	bytes, _ = json.Marshal(user)
	return ctx.GetStub().PutState(id, bytes)
}

// 降级用户

func (s *SmartContract) DegradeUser(ctx contractapi.TransactionContextInterface, id string) error {
	if exists, _ := s.UserExists(ctx, id); !exists {
		return fmt.Errorf("该用户Id:%s不存在", id)
	}
	bytes, _ := ctx.GetStub().GetState(id)
	var user Users
	json.Unmarshal(bytes, &user)
	if user.IsCA > 0 {
		user.IsCA -= 1
	}
	bytes, _ = json.Marshal(user)
	return ctx.GetStub().PutState(id, bytes)
}

// 获取历史

func (s *SmartContract) GetHistory(ctx contractapi.TransactionContextInterface, ID string) ([]HistoryQueryResult, error) {
	log.Printf("GetHistory: ID %v", ID)
	exists, err := s.UserExists(ctx, ID)
	if !exists {
		return nil, err
	}
	resultsIterator, err := ctx.GetStub().GetHistoryForKey(ID)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	log.Printf("查询用户历史\n")
	var records []HistoryQueryResult
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var user Users
		if len(response.Value) > 0 {
			err = json.Unmarshal(response.Value, &user)
			if err != nil {
				return nil, err
			}
		} else {
			user = Users{
				ID: ID,
			}
		}
		timestamp := response.Timestamp.AsTime()
		if err != nil {
			return nil, err
		}
		record := HistoryQueryResult{
			TxId:      response.TxId,
			Timestamp: timestamp,
			Record:    &user,
			IsDelete:  response.IsDelete,
		}
		records = append(records, record)
	}
	return records, nil
}

// 修改登录时间

func (s *SmartContract) UpdateLoginTime(ctx contractapi.TransactionContextInterface, id string) error {
	user, _ := s.ReadUser(ctx, id)
	// 更新登录时间
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	user.LastLoginTime = strconv.FormatInt(timestamp.GetSeconds(), 10)
	bytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, bytes)
}
func main() {
	userChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err = userChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
}
