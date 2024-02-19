package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"strconv"
	"time"
)

// 用于颁发终端证书

type IntermediateCAContract struct {
	contractapi.Contract
}

var keyBytes = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0pR3EYb61Oo5f+f1Djmnv6TzApqjnUFsiF89HrTia6QtFt/7\nYdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd604xdV8HnHO2e139Pg7pu2ZGDFHiV\nrAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3orCxbjetHqgfnmKJgZPbO7vW+bGUJ\n9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11lCNXKmzbLPvQnRA0wB0a9z96Qn7gm\nmL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTmkGHT75Naeg6GXgghY1ceK5JdH+Fo\nOoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8hQwIDAQABAoIBAQCK/OL59pVoIpCB\nE6BzGyrVGxIqDdcf3Ca+e93jfpBTa7E2/+7zyL7dVFEiT6wvsc67MDeIliN9P3+W\nG+koQpEXP/X8Dkd0mIHWyni5ATxY7eoOgOiI/dIL0QXVYnsfAgDpdE9u6oVM13/L\nSfabsyV3Pm/PZBOQ7la2L7Zf7Wb34JigiZot7j6f5SxCgf+zTL7yC1nuph5OO8dP\nQFndf4ZTaKf4XepRLnkTqsf4AGIGrIcL4jvaf+7t5WAInILvnzaAwq/8QGnwwGYh\nzFsyq+ApYyeKlR5DWdYNEKr6/brAa96ehya4xJe4senCbFbz4xKdtNlHFq+YuN+h\nI/pBKY2BAoGBAOtpALgHpWHHsRFfILXUURMt9Dzt9dp5t9SwHQrZNFkrAMjb/tg9\ntVaa/tcgtt5RV+qsPO0Qn9hoKD0HQ96OZQ8mI4OjWG0ab8PVNNDDdo3qh+fcdSr6\nmbqCWflUeFD9KIyg1/3l74i+edsasfu87D0bve9hsnAs3ryV+C1M6iiJAoGBAOT/\nfw3wg77nUfMrhMy8rskj3ttJe4Ed4BSJ0T4hixPNpU8y8dx5Ny3TH7Olgag/O55H\nUtcSQTL6IsdE2xgSMTSSdbHyWwpCRrN3d1veuI2k7ptc8zzYwBF2mqZO7OBqLBS1\nKp8G7mCSi4Q9RHqMYA9dkRLRoIcDRLybj8+ekrBrAoGAOKruIV610PPhC+16Ukrp\nuVQ2lvQxWoYyWmCKnTHsCAryBWfv0N4J6O8mqWKWoq2yHCuZ/vchg1aPWSGGlOxy\nJ1Nm+Sk5AAp9HQcVz6s9vqvWS1omWlI470yxm/NZgyVtvWx6kgPnxWMUskmazp6L\nv6oN7rH14krq0zrGoyEAvQECgYAcrFkuV6VHbBN4zUQtlpqUGOe4sXTDcAg0yiTn\nELAnZKKETi62mn7sP/lCN0EK3hAK+4dF4sVDKsrcBKUiWHTMzmHqTBxWJoJPym+p\nkzOsmLA/x921CrbR+PXYSR2j4+dtGFoj22xRr0fE4R8H8Te99MtLffAJt8ENlLTn\nHEXlzQKBgQCsCSkBXa4YF2k3Alsc3skTgK/KAvYr3bDBjoSGY+xrYJ7oipIeTbv6\n+fYxIUrsiUgeRYPl7UxVKwtg0kJByVy3oEMMS7Csb5D6oUbormUjeVclAYoTatj7\nj6p0JvXqXopuBchK2uazTT5beCPzCGy6NrmxRcrTHAeGNXi79cxTzw==\n-----END RSA PRIVATE KEY-----\n")

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
	// 包含的字节数组 csr或者cert
	Bytes []byte `json:"certBytes"`
	// 证书的hash值
	CertHashValue string `json:"certHashValue"`
	// 所拥有的证书的用户的Id
	UserId string `json:"userId"`
	// 状态
	Status int `json:"status"`
}

// 状态
const (
	reviewing = iota // 审核中
	approved         // 已批准
	revoked          // 撤销
)

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

// 用户向中间CA请求证书 用户Id，csr 保存上区块链上

func (I *IntermediateCAContract) RequestCert(ctx contractapi.TransactionContextInterface, userId, csr string) error {
	// 查询用户Id是否存在
	exists, err := I.UserExists(ctx, userId)
	log.Printf("该用户在区块链上%v", exists)
	if err != nil || !exists {
		return fmt.Errorf("该用户Id不在区块链%s\n错误:%v", userId, err)
	}
	request, err := pareCsr([]byte(csr))
	if err != nil {
		return err
	}
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	var cert = Certs{
		CertId:        strconv.FormatInt(txTimestamp.GetSeconds(), 10),
		Version:       request.Version,
		BeginDate:     time.Time{},
		EndDate:       time.Time{},
		Subject:       request.Subject,
		Issuer:        pkix.Name{},
		Bytes:         []byte(csr),
		CertHashValue: fmt.Sprintf("%x", sha256.Sum256([]byte(csr))),
		UserId:        userId,
		Status:        0,
	}
	log.Printf("证书信息为%v", cert)
	certBytes, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	return ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), certBytes)
}

// 向根CA调用中间证书来颁发

func (*IntermediateCAContract) ReadIntermediateCert(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	args := make([][]byte, 1)
	args[0] = []byte("GetNewCert")
	return ctx.GetStub().InvokeChaincode("RootCA", args, "").Payload, nil
}

// 查看用户Id是否存在 向user链码查看

func (*IntermediateCAContract) UserExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	args := make([][]byte, 2)
	args[0] = []byte("UserExists")
	args[1] = []byte(id)
	response := ctx.GetStub().InvokeChaincode("user", args, "")
	log.Printf("response:%v", response)
	log.Printf("payload:%s", response.GetPayload())
	if response.Status != shim.OK {
		return false, fmt.Errorf("stauts:%d,error:%s", response.GetStatus(), response.GetMessage())
	}
	return bytes.Equal(response.GetPayload(), []byte("true")), nil
}

// 查看证书是否在区块链上

func (*IntermediateCAContract) CertExists(ctx contractapi.TransactionContextInterface, Cert string) (bool, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return false, err
	}
	defer resultsIterator.Close()
	for resultsIterator.HasNext() {
		kv, err := resultsIterator.Next()
		if err != nil {
			return false, err
		}
		var cert Certs
		json.Unmarshal(kv.GetValue(), &cert)
		// 比较Hash值
		if fmt.Sprintf("%s", sha256.Sum256([]byte(Cert))) == cert.CertHashValue {
			return false, nil
		}
	}
	return true, nil
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

// 颁发证书

func (I *IntermediateCAContract) IssuerCert(ctx contractapi.TransactionContextInterface, id string) error {
	// 提取中间证书
	certBytes, _ := I.ReadIntermediateCert(ctx)
	// 解析中间证书
	x509Cert, err := parseX509Cert(certBytes)
	if err != nil {
		return err
	}
	// 添加中间证书
	log.Printf("证书信息:%v", *x509Cert)
	// 提取证书的csr
	state, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var cert = Certs{}
	json.Unmarshal(state, &cert)
	log.Printf("证书%v", cert)
	// 解析要签名的证书
	certificate, err := parseX509Cert(cert.Bytes)
	if err != nil {
		return err
	}
	// 获取时间戳 并且赋值
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	certificate.SerialNumber = big.NewInt(timestamp.GetSeconds())
	certificate.NotBefore = time.Unix(timestamp.GetSeconds(), 0)
	certificate.NotAfter = time.Unix(timestamp.GetSeconds(), 0).AddDate(1, 0, 0)
	log.Printf("父证书%v", *certificate)
	// 获取证书的公钥

	// 获取签名者的私钥
	privateKey, _ := parsePrivateKey(keyBytes)
	// 创建证书
	createCertificate, err := x509.CreateCertificate(rand.Reader, certificate, x509Cert, certificate.PublicKey, privateKey)
	if err != nil {
		return err
	}
	// pem编码
	log.Printf("创建证书成功,cert字节为:%s", createCertificate)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   createCertificate,
	})
	log.Printf("pem证书为%s\n", pemBytes)
	// 改变证书状态并存入
	cert.CertId = strconv.FormatInt(timestamp.GetSeconds(), 10)
	cert.Status = approved
	cert.CertHashValue = fmt.Sprintf("%x", sha256.Sum256(certBytes))
	marshal, _ := json.Marshal(cert)
	return ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), marshal)
}

// 获得所有证书信息

func (I *IntermediateCAContract) GetAllCerts(ctx contractapi.TransactionContextInterface) ([]Certs, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	var certs []Certs
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert Certs
		err = json.Unmarshal(queryResponse.Value, &cert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// 撤销证书(软删除)

func (I *IntermediateCAContract) RevokeCert(ctx contractapi.TransactionContextInterface, id string) error {
	// 检查用户权限

	// 调用证书
	state, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var cert Certs
	if err = json.Unmarshal(state, &cert); err != nil {
		return err
	}
	cert.Status = revoked
	state, _ = json.Marshal(cert)
	return ctx.GetStub().PutState(id, state)
}

// 拒绝证书 证书的Id

func RejectCert(ctx contractapi.TransactionContextInterface, id string) error {
	return ctx.GetStub().DelState(id)
}

// 将csr转为结构体

func ConveyCsr(request x509.CertificateRequest) (cert Certs) {
	cert.Subject = request.Subject
	cert.Version = request.Version
	return
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

func parsePrivateKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("密钥对格式错误，为%s", block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// 加载公钥

// 解析csr

func pareCsr(bytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("密钥对格式错误，为%s", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// 将Request转为Cert

func conveyCertificateRequestToCertificate(certificateRequest *x509.CertificateRequest) x509.Certificate {
	var certificate = x509.Certificate{
		Raw:                         certificateRequest.Raw,
		RawTBSCertificate:           certificateRequest.RawTBSCertificateRequest,
		RawSubjectPublicKeyInfo:     certificateRequest.RawSubjectPublicKeyInfo,
		RawSubject:                  certificateRequest.RawSubject,
		RawIssuer:                   nil,
		Signature:                   certificateRequest.Signature,
		SignatureAlgorithm:          certificateRequest.SignatureAlgorithm,
		PublicKeyAlgorithm:          certificateRequest.PublicKeyAlgorithm,
		PublicKey:                   certificateRequest.PublicKey,
		Version:                     certificateRequest.Version,
		SerialNumber:                nil,
		Issuer:                      pkix.Name{},
		Subject:                     certificateRequest.Subject,
		NotBefore:                   time.Time{},
		NotAfter:                    time.Time{},
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign, //
		Extensions:                  certificateRequest.Extensions,
		ExtraExtensions:             certificateRequest.ExtraExtensions,
		UnhandledCriticalExtensions: nil,
		ExtKeyUsage:                 nil,
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       true, //
		IsCA:                        true, //
		MaxPathLen:                  0,    //
		MaxPathLenZero:              true,
		SubjectKeyId:                nil,
		AuthorityKeyId:              nil,
		OCSPServer:                  nil,
		IssuingCertificateURL:       nil,
		DNSNames:                    certificateRequest.DNSNames,
		EmailAddresses:              certificateRequest.EmailAddresses,
		IPAddresses:                 certificateRequest.IPAddresses,
		URIs:                        certificateRequest.URIs,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
		ExcludedDNSDomains:          nil,
		PermittedIPRanges:           nil,
		ExcludedIPRanges:            nil,
		PermittedEmailAddresses:     nil,
		ExcludedEmailAddresses:      nil,
		PermittedURIDomains:         nil,
		ExcludedURIDomains:          nil,
		CRLDistributionPoints:       nil,
		PolicyIdentifiers:           nil,
	}
	return certificate
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
