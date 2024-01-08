package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"math/big"
	"time"
)

type IntermediateCAContract struct {
	contractapi.Contract
}

// 证书

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
	// 证书的字节数组
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

func (*IntermediateCAContract) IssueCert(ctx contractapi.TransactionContextInterface) error {

	return nil
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
