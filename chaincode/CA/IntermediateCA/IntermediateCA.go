package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"math/big"
	"time"
)

// 用于颁发终端证书

type IntermediateCAContract struct {
	contractapi.Contract
}

// 证书 其中用户能够拥有多张证书，区块链中只存证书的基础信息

type Certs struct {
	// 证书的主键
	CertId string `json:"certId"`
	// 版本号
	Version int `json:"version"`
	// 开始时间
	BeginDate time.Time `json:"beginDate"`
	// 结束时间
	EndDate time.Time `json:"endDate"`
	// subject
	Subject pkix.Name `json:"subject"`
	// 颁发者
	Issuer pkix.Name `json:"issuer"`
	// 证书的字节数组(pem编码)
	CertBytes []byte `json:"certBytes"`
	// 证书的hash值
	CertHashValue string `json:"certHashValue"`
	// 所拥有的证书的用户的Id
	UserId string `json:"userId"`
}

// 证书的Id

type CertId struct {
	UserId string
	Id     string
}

var key, _ = rsa.GenerateKey(rand.Reader, 1024)

// 中间证书CSR
var interCsr = &x509.Certificate{
	Version:      3,
	SerialNumber: big.NewInt(time.Now().Unix()),
	Subject: pkix.Name{
		Country:            []string{"CN"},
		Province:           []string{"Shanghai"},
		Locality:           []string{"Shanghai"},
		Organization:       []string{"CAUC"},
		OrganizationalUnit: []string{"CAUC"},
		CommonName:         "Inter CA",
	},
	NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
	NotAfter:              time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
	BasicConstraintsValid: true,
	IsCA:                  true,
	MaxPathLen:            0,
	MaxPathLenZero:        true,
	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
}

// 向根CA申请中间证书

func (*IntermediateCAContract) Request(ctx contractapi.TransactionContextInterface) error {
	// 调用根证书的链码
	response := ctx.GetStub().InvokeChaincode("RootCA", nil, "")
	if response.Status == shim.ERROR || response.Status == shim.ERRORTHRESHOLD {
		return errors.New("调用RootCA链码失败")
	}
	log.Println("调用成功")
	return nil
}

// 初始化

func Init() {

}

// 颁发用户的证书

func (I *IntermediateCAContract) IssueCert(ctx contractapi.TransactionContextInterface, id string) error {
	bytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var cert Certs
	err = json.Unmarshal(bytes, &cert)
	if err != nil {
		return err
	}

	return nil
}

// 用户向中间CA请求证书 用户Id，csr

func (I *IntermediateCAContract) RequestCert(ctx contractapi.TransactionContextInterface, id, csr string) error {
	// 查询用户Id是否存在

	return nil
}

// 向根CA调用中间证书来颁发

func (*IntermediateCAContract) ReadRootCert(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	args := make([][]byte, 1)
	args[0] = []byte("GetNewCert")
	response := ctx.GetStub().InvokeChaincode("RootCA", args, "")
	log.Printf("response:%v", response)
	return response.Payload, nil
}

// 查看用户Id是否存在

func (*IntermediateCAContract) UserExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	args := make([][]byte, 2)
	args[0] = []byte("UserExists")
	args[1] = []byte(id)
	response := ctx.GetStub().InvokeChaincode("user", args, "")
	log.Printf("response:%v", response)
	if response.Status != 0 {
		return false, fmt.Errorf("%v", response.GetMessage())
	}
	return bytes.Equal(response.GetPayload(), []byte("True")), nil
}

// 生成证书请求

func CreateCsr(subject pkix.Name, dns, emails []string, pri *rsa.PrivateKey) ([]byte, error) {
	certificateRequest := x509.CertificateRequest{
		Raw:                      nil,
		RawTBSCertificateRequest: nil,
		RawSubjectPublicKeyInfo:  nil,
		RawSubject:               nil,
		Version:                  3,
		Signature:                nil,
		SignatureAlgorithm:       0,
		PublicKeyAlgorithm:       0,
		PublicKey:                nil,
		Subject:                  subject,
		Extensions:               nil,
		ExtraExtensions:          nil,
		DNSNames:                 dns,
		EmailAddresses:           emails,
		IPAddresses:              nil,
		URIs:                     nil,
	}
	return x509.CreateCertificateRequest(rand.Reader, &certificateRequest, pri)
}

// 生成证书

func ICert() {

}

// 加载x509证书

func parseX509Cert(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pem证书加载失败,其格式为%s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// 加载公私密钥

func parseKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("密钥对格式错误，为%s", block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func main() {
	InterCAChaincode, err := contractapi.NewChaincode(&IntermediateCAContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err := InterCAChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
	log.Printf("Init InterCA chaincode Successfully!")
}
