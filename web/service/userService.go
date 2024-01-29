package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"web/gateway"
)

const (
	SignValue = "Secret"
	Length    = 1024
)

var (
	userContract = gateway.InitConfigContract("mychannel", "user")
)

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
	fmt.Printf("私钥为:\n%s\n", privateKey)
	fmt.Printf("公钥为:\n%s\n", publicKey)
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

// 注册服务 用户自己提交公钥

func RegisterService(id, password, email, publicKey string) error {
	_, err := userContract.SubmitTransaction("CreateUser", id, password, email, publicKey)
	return err
}

// 注册并且生成密钥

func RegisterServiceWithGenRsaKey(id, password, email string) (error, []byte) {
	privateKey, publicKey := GenRsaKey(1024)
	_, err := userContract.SubmitTransaction("CreateUser", id, password, email, publicKey)
	return err, []byte(privateKey)
}

// 登录 附带 签名

func LoginService(id, password string, signature []byte) error {
	_, err := userContract.SubmitTransaction("VerifyPassword", id, password)
	if err != nil {
		return err
	}
	// 验证签名
	Flag := VerifySignService(id, signature)
	if Flag == false {
		return errors.New("签名值错误")
	}
	return nil
}

// user 信息

func UserInfoService(Id string) ([]byte, error) {
	return userContract.SubmitTransaction("ReadUser", Id)
}

func AllUserInfoService() ([]byte, error) {
	return userContract.SubmitTransaction("GetAllUsers")
}

// 修改密码

func UpdateService(Id, password string) error {
	_, err := userContract.SubmitTransaction("UpdatePassword", Id, password)
	return err
}

// 签名 后期做成前端签名

func SignService(originMessage string, file []byte) (sign []byte, err error) {
	// 加载私钥
	key, err := LoadPrivateKey(file)
	if err != nil {
		return
	}
	// 用私钥签名
	sign, err = SignWithRsa(originMessage, key)
	return
}

// 验证签名

func VerifySignService(id string, sign []byte) bool {
	bytes, err := userContract.SubmitTransaction("ReadUser", id)
	if err != nil {
		return false
	}
	var user = struct {
		// 唯一Id
		ID string `json:"Id"`
		// RSA 公钥
		PublicKey string `json:"publicKey"`
	}{}
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		return false
	}
	// 编码
	key, err := LoadPublicKey([]byte(user.PublicKey))
	if err != nil {
		return false
	}
	err = Verify(*key, id, string(sign))
	if err != nil {
		return false
	}
	return true
}

// 私钥签名 签名的信息为用户Id

func SignWithRsa(originMessage string, privateKey *rsa.PrivateKey) (signature []byte, err error) {
	hashed := sha256.Sum256([]byte(originMessage))
	// 签名
	signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("签名失败:", err)
		return
	}
	return
}

// 加载私钥文件

func LoadPrivateKey(file []byte) (*rsa.PrivateKey, error) {
	// 解码PEM格式的私钥文件
	privateKeyBlock, _ := pem.Decode(file)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("无法解析PEM格式的私钥文件")
	}
	// 解析RSA私钥
	return x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
}

// 加载公钥文件

func LoadPublicKey(file []byte) (*rsa.PublicKey, error) {
	// 解码PEM格式的私钥文件
	publicKeyBlock, _ := pem.Decode(file)
	if publicKeyBlock == nil || publicKeyBlock.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("无法解析PEM格式的公钥文件%s", publicKeyBlock.Type)
	}
	// 解析RSA私钥
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	// 成功直接返回
	if err == nil {
		return publicKey, nil
	}
	// 解析格式
	key, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("无法解析RSA公钥: %v", err)
}

// 验证   1公钥2数据3签名值

func Verify(publicKey rsa.PublicKey, data string, sign string) (err error) {
	signature, err := hex.DecodeString(sign)
	hashed := sha256.Sum256([]byte(data))
	return rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], signature)
}

// 查询历史

func UsersHistoryService(id string) ([]byte, error) {
	return userContract.SubmitTransaction("GetHistory", id)
}
