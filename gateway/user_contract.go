package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
)

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
	// RSA 公密钥
	PublicKey string `json:"publicKey"`
	//// RSA 私钥
	SecretKey string `json:"secretKey"`
	// 证书Id
	CertId string `json:"certId"`
}

// 添加连接

var UserContract = Init()

// 用户注册

func CreateUser(contract *client.Contract, userId, username, password, email, createTime, key string) error {
	fmt.Println("\n--> Evaluate Transaction: CreateUser, function add user")
	_, err := contract.SubmitTransaction("CreateUser", userId, username, password, email, createTime, key)
	if err != nil {
		return err
	}
	println("添加成功")
	return err
}

// 查询账本

func QueryUser(contract *client.Contract, userId string) (Users, error) {
	transaction, err := contract.EvaluateTransaction("ReadUser", userId)
	if err != nil {
		return Users{}, err
	}
	// 解析json
	users := Users{}
	err = json.Unmarshal([]byte(transaction), &users)
	return users, err
}

// 判断某个用户存在

func IsExistUser(contract *client.Contract, userId string) (bool, error) {
	transaction, err := contract.EvaluateTransaction("UserExists", userId)
	println(string(transaction))
	if err != nil {
		return true, err
	}
	if string(transaction) == "true" {
		return true, err
	}
	return false, err
}

// 修改用户的密码

func UpdatePassword(contract *client.Contract, userId, password string) error {
	_, err := contract.SubmitTransaction("UpdatePassword", userId, password)
	if err != nil {
		return err
	}
	return nil
}
