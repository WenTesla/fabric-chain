package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
)

type Users struct {
	// 唯一Id
	ID string `json:"Id"`
	// 密码
	Password string `json:"password"`
	// 邮箱
	Email string `json:"email"`
	// 是否为CA 0-为普通用户 1-为CA 普通用户只拥有申请证书和查看证书权限，而CA审核方拥有查询、撤销、审核申请者身份等权限
	IsCA int `json:"isCA"`
	//// 创建时间
	CreateTime string `json:"createTime"`
	//// 修改时间
	UpdateTime string `json:"updateTime"`
	// 上次登录时间 时间戳
	LastLoginTime string `json:"lastLoginTime"`
	// RSA 公钥
	PublicKey string `json:"publicKey"`
	// 证书Id
	CertId string `json:"certId"`
	//状态 0-正常 1-禁用
	Status int `json:"status"`
}

// 添加连接

var UserContract = InitUserContract()

// 用户注册

func CreateUser(contract *client.Contract, userId, password, email, key string) error {
	fmt.Println("\n--> Evaluate Transaction: CreateUser, function add user")
	_, err := contract.SubmitTransaction("CreateUser", userId, password, email, key)
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

func IsExistUser(contract *client.Contract, id string) (bool, error) {
	transaction, err := contract.EvaluateTransaction("UserExists", id)
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

// 创建Ca用户

func CreateCaUser(contract *client.Contract, userId, password, email, createTime string) error {
	_, err := contract.SubmitTransaction("CreateCAUser", userId, password, email, createTime, createTime)
	return err
}

// 查询所有用户

func QueryAllUsers(contract *client.Contract) ([]Users, error) {
	bytes, err := contract.EvaluateTransaction("GetAllUsers")
	if err != nil {
		return nil, nil
	}
	var users []Users
	err = json.Unmarshal(bytes, &users)
	if err != nil {
		return nil, nil
	}
	return users, err
}
