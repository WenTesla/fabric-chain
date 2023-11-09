package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	gateway "gateway"
	"log"
	"time"
	"web/config"
)

const name = ""

// 生成公私密钥对 返回pem格式

func GenRsaKey(bits int) (privateKey, publicKey string) {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(priKey)
	marshalPKCS1PublicKey := x509.MarshalPKCS1PublicKey(&priKey.PublicKey)
	// pem 编码 公钥
	memoryPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   marshalPKCS1PublicKey,
	})
	publicKey = string(memoryPublicKey)
	memoryPrivateKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalPKCS1PrivateKey,
	})
	privateKey = string(memoryPrivateKey)
	//privateKey = base64.StdEncoding.EncodeToString(marshalPKCS1PrivateKey)
	//publicKey = base64.StdEncoding.EncodeToString(marshalPKCS1PublicKey)

	fmt.Printf("私钥为:\n%x\n", privateKey)
	fmt.Printf("公钥为:\n%x\n", publicKey)
	return
}

// 解析公钥

func ParsePublicKey(publicKey string) ([]byte, error) {
	decodeString, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	// 对公钥信息进行编码
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: decodeString,
	}
	pemData := pem.EncodeToMemory(block)
	return pemData, nil
}

// 解析私钥

func ParsePrivateKey(privateKey string) ([]byte, error) {
	decodeString, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	// 对公钥信息进行编码
	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   decodeString,
	}
	pemData := pem.EncodeToMemory(block)
	return pemData, nil
}

// 匹配 RSA 公私密钥

func MatchRSAKey(publicKey string, privateKey string) bool {
	// Handle errors here
	block, _ := pem.Decode([]byte(privateKey))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pubBlock, _ := pem.Decode([]byte(publicKey))
	// 有问题
	key.Public()
	pubKey, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	if err != nil {
		return false
	}
	//pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return key.PublicKey.Equal(pubKey)
}

// hash密码

func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	bytes := hash.Sum(nil)
	// 密码加密
	fmt.Printf("密码为:%x", bytes)
	return hex.EncodeToString(bytes)
}

// 注册服务

func RegisterService(username, password, email, publicKey string) error {
	// 先看是否存在当前Id
	IsExist, err := gateway.IsExistUser(gateway.UserContract, username)
	if IsExist {
		return errors.New(config.UserIsExist)
	}
	password = hashPassword(password)
	//_, publicKey := GenRsaKey(1024)
	encodeToString := base64.StdEncoding.EncodeToString([]byte(publicKey))
	err = gateway.CreateUser(gateway.UserContract, username, username, password, email, time.Now().String(), encodeToString)
	if err != nil {
		return err
	}
	return nil
}

// 注册并且生成密钥

func RegisterServiceWithGenRsaKey(username, password, email string) (error, []byte) {
	// 先看是否存在当前Id
	//user, err := gateway.QueryUser(gateway.UserContract, username)
	//if err != nil {
	//	return err, nil
	//}
	//
	//if user.ID != "" {
	//	return errors.New("当前用户昵称已存在"), nil
	//}
	isExistUser, err := gateway.IsExistUser(gateway.UserContract, username)
	if isExistUser {
		return errors.New(config.UserIsExist), nil
	}
	password = hashPassword(password)
	privateKey, publicKey := GenRsaKey(1024)
	//parsePrivateKey, err := ParsePrivateKey(privateKey)
	//key, err := ParsePublicKey(publicKey)

	err = gateway.CreateUser(gateway.UserContract, username, username, password, email, time.Now().String(), publicKey)
	if err != nil {
		return err, nil
	}
	return nil, []byte(privateKey)
}

// 登录 附带 密钥

func LoginService(username, password string, file []byte) error {
	user, err := gateway.QueryUser(gateway.UserContract, username)
	if err != nil {
		return errors.New(config.UserIdOrPasswordFalse)
	}
	password = hashPassword(password)
	if user.Password != password {
		return errors.New("账户名或密码错误")
	}
	// 验证密钥对
	// 解析公钥文件
	block, _ := pem.Decode(file)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Println("failed to decode PEM block containing  key")
		return errors.New("解析错误")
	}

	//// 解析公钥
	//PublicKeyByte, err := base64.StdEncoding.DecodeString(user.PublicKey)
	//if err != nil {
	//	return err
	//}
	// 解析私钥
	//decodeString, err := base64.StdEncoding.DecodeString(user.PublicKey)
	if err != nil {
		return err
	}
	// 判断公私密钥是否匹配
	IsMatch := MatchRSAKey(string(user.PublicKey), string(file))
	if !IsMatch {
		return errors.New("公私密钥不匹配")
	}
	return nil
}

func UserInfoService(Id string) (gateway.Users, error) {
	user, err := gateway.QueryUser(gateway.UserContract, Id)
	// 如果非空
	if user.ID == "" {
		return user, errors.New("用户为空")
	}
	return user, err
}

// 修改密码

func UpdateService(Id string, password string) error {
	user, err := gateway.QueryUser(gateway.UserContract, Id)
	// 如果非空
	if user.ID == "" {
		return errors.New("用户为空")
	}

	password = hashPassword(password)
	err = gateway.UpdatePassword(gateway.UserContract, Id, password)
	return err
}
