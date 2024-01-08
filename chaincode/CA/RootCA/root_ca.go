package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"math/big"
	"time"
)

type RootCAContract struct {
	contractapi.Contract
}

// 私钥

var keyBytes = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0pR3EYb61Oo5f+f1Djmnv6TzApqjnUFsiF89HrTia6QtFt/7\nYdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd604xdV8HnHO2e139Pg7pu2ZGDFHiV\nrAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3orCxbjetHqgfnmKJgZPbO7vW+bGUJ\n9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11lCNXKmzbLPvQnRA0wB0a9z96Qn7gm\nmL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTmkGHT75Naeg6GXgghY1ceK5JdH+Fo\nOoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8hQwIDAQABAoIBAQCK/OL59pVoIpCB\nE6BzGyrVGxIqDdcf3Ca+e93jfpBTa7E2/+7zyL7dVFEiT6wvsc67MDeIliN9P3+W\nG+koQpEXP/X8Dkd0mIHWyni5ATxY7eoOgOiI/dIL0QXVYnsfAgDpdE9u6oVM13/L\nSfabsyV3Pm/PZBOQ7la2L7Zf7Wb34JigiZot7j6f5SxCgf+zTL7yC1nuph5OO8dP\nQFndf4ZTaKf4XepRLnkTqsf4AGIGrIcL4jvaf+7t5WAInILvnzaAwq/8QGnwwGYh\nzFsyq+ApYyeKlR5DWdYNEKr6/brAa96ehya4xJe4senCbFbz4xKdtNlHFq+YuN+h\nI/pBKY2BAoGBAOtpALgHpWHHsRFfILXUURMt9Dzt9dp5t9SwHQrZNFkrAMjb/tg9\ntVaa/tcgtt5RV+qsPO0Qn9hoKD0HQ96OZQ8mI4OjWG0ab8PVNNDDdo3qh+fcdSr6\nmbqCWflUeFD9KIyg1/3l74i+edsasfu87D0bve9hsnAs3ryV+C1M6iiJAoGBAOT/\nfw3wg77nUfMrhMy8rskj3ttJe4Ed4BSJ0T4hixPNpU8y8dx5Ny3TH7Olgag/O55H\nUtcSQTL6IsdE2xgSMTSSdbHyWwpCRrN3d1veuI2k7ptc8zzYwBF2mqZO7OBqLBS1\nKp8G7mCSi4Q9RHqMYA9dkRLRoIcDRLybj8+ekrBrAoGAOKruIV610PPhC+16Ukrp\nuVQ2lvQxWoYyWmCKnTHsCAryBWfv0N4J6O8mqWKWoq2yHCuZ/vchg1aPWSGGlOxy\nJ1Nm+Sk5AAp9HQcVz6s9vqvWS1omWlI470yxm/NZgyVtvWx6kgPnxWMUskmazp6L\nv6oN7rH14krq0zrGoyEAvQECgYAcrFkuV6VHbBN4zUQtlpqUGOe4sXTDcAg0yiTn\nELAnZKKETi62mn7sP/lCN0EK3hAK+4dF4sVDKsrcBKUiWHTMzmHqTBxWJoJPym+p\nkzOsmLA/x921CrbR+PXYSR2j4+dtGFoj22xRr0fE4R8H8Te99MtLffAJt8ENlLTn\nHEXlzQKBgQCsCSkBXa4YF2k3Alsc3skTgK/KAvYr3bDBjoSGY+xrYJ7oipIeTbv6\n+fYxIUrsiUgeRYPl7UxVKwtg0kJByVy3oEMMS7Csb5D6oUbormUjeVclAYoTatj7\nj6p0JvXqXopuBchK2uazTT5beCPzCGy6NrmxRcrTHAeGNXi79cxTzw==\n-----END RSA PRIVATE KEY-----\n")

// 根证书

var rootCertBytes = []byte("-----BEGIN CERTIFICATE-----\nMIIDbzCCAlcCFD/oOgfjWvIj8iIwRumGUXK9yjy3MA0GCSqGSIb3DQEBCwUAMHQx\nCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVIVUJFSTELMAkGA1UEBwwCWFkxDTALBgNV\nBAoMBENBVUMxDTALBgNVBAsMBENBVUMxDjAMBgNVBAMMBWJvd2VuMRowGAYJKoZI\nhvcNAQkBFgsxMjNAMTYzLmNvbTAeFw0yNDAxMDEwNDEyMThaFw0zMzEyMjkwNDEy\nMThaMHQxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVIVUJFSTELMAkGA1UEBwwCWFkx\nDTALBgNVBAoMBENBVUMxDTALBgNVBAsMBENBVUMxDjAMBgNVBAMMBWJvd2VuMRow\nGAYJKoZIhvcNAQkBFgsxMjNAMTYzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBANKUdxGG+tTqOX/n9Q45p7+k8wKao51BbIhfPR604mukLRbf+2HQ\nq224Nt2tzGOaq5ByTzb0eMCfEF4Y5lDXetOMXVfB5xztntd/T4O6btmRgxR4lawL\ntmL4q88wJ2aU8zyuYXUNC4x07L8ldkGt6KwsW43rR6oH55iiYGT2zu71vmxlCfSc\nue6GeZQ/WbDXoTmAmBANG7Nl2gvQUlddZQjVyps2yz70J0QNMAdGvc/ekJ+4Jpi+\n6puPUyn2yaAsb1+8rQhUAYZYAQrIFzo05pBh0++TWnoOhl4IIWNXHiuSXR/haDqI\nsQGJY0BrptE9kLRAU0e64eD6kYqQJs3fIUMCAwEAATANBgkqhkiG9w0BAQsFAAOC\nAQEAbdG7dk0WVDXrcKbp5B1hyMGI4qmHcwwFpr5nJup5PeNY0yJAcIDahuB4Lilg\ndD1ZBjvNmYb1rn3Ynfo6PHTIwS20wbSIle5bbldyJC0qhdcyIzYNlg9hG5sT/qPd\ntkfRxlmIGLB/iCPdQcTJBrnYzX0iRbikQz6U+IxERhfhMUBLAleG02lmknyOr7Fm\n794NOlz+IDF03aRvrrNcYZSezlTyOkEAJFy6LitgMPE3/+VTJFWaBqaqT0p3UZNX\nxrLwbE0TOeOZNO40rC1yG2FlpHYvRWvGCKaLNRRG+jxWmE7PUuhKNCFM1PxrihkH\ny4Cpwt/jYOk/vmhDvxEj2Thr7g==\n-----END CERTIFICATE-----\n")

// 根证书模板
var rootCsr = x509.Certificate{
	SerialNumber: big.NewInt(2024),
	Subject: pkix.Name{
		Organization: []string{"CAUC"},
		Country:      []string{"CN"},
		Province:     []string{"TJ"},
		Locality:     []string{"TJ"},
		CommonName:   "Root CA",
	},
	NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
	NotAfter:              time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
	BasicConstraintsValid: true,
	IsCA:                  true,
	MaxPathLen:            1,
	MaxPathLenZero:        false,
	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
}

// 根证书Id
const rootCertID = "root_cert_id"

// 根证书密钥Id
const rootCertKey = "root_key"

// 根证书和密钥是否匹配

func InitLedger() error {
	// 是否匹配
	_, err := tls.X509KeyPair(rootCertBytes, keyBytes)
	if err != nil {
		return err
	}
	fmt.Println("根证书和密钥对匹配成功")
	return nil
}

// 加载证书

func loadCert(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// 加载公私

func loadKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, nil
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil
	}
	return privateKey, err
}

// 签发中间证书 csr，pubBytes皆为序列化的对象数组 return the certificate in DER encoding

func (s *RootCAContract) SignIntermediateCert(ctx contractapi.TransactionContextInterface, csrBytes string, pubBytes string) (cert string, err error) {
	// 加载根证书的私钥
	bytes, err := ctx.GetStub().GetState(rootCertKey)
	if err != nil {
		return "", fmt.Errorf("私钥加载失败")
	}

	RootKey, err := loadKey(bytes)
	if err != nil {
		return "", fmt.Errorf("私钥加载失败")
	}
	log.Println("私钥")
	var csr = x509.Certificate{}
	err = json.Unmarshal([]byte(csrBytes), &csr)
	if err != nil {
		return
	}
	var pub = rsa.PublicKey{}
	err = json.Unmarshal([]byte(pubBytes), &pub)
	if err != nil {
		return
	}
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&csr,
		&rootCsr,
		&pub,
		RootKey,
	)
	cert = string(certBytes)
	log.Println("cert:\n" + hex.EncodeToString(certBytes))
	return
}

// 返回pem编码的证书

func (s *RootCAContract) SignIntermediatePemCert(ctx contractapi.TransactionContextInterface, csrBytes string, pubBytes string) (string, error) {
	cert, err := s.SignIntermediateCert(ctx, csrBytes, pubBytes)
	if err != nil {
		return "", err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte(cert),
	}
	pemData := pem.EncodeToMemory(certBlock)
	return string(pemData), nil
}

// 加载

func loadCertAndKey(certBytes, keyBytes []byte) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	cert, err = loadCert(certBytes)
	key, err = loadKey(keyBytes)
	return
}

// 加载私钥

func LoadRootKey(ctx contractapi.TransactionContextInterface) (key *rsa.PrivateKey, err error) {
	bytes, err := ctx.GetStub().GetState(rootCertKey)
	err = json.Unmarshal(bytes, &key)
	return
}

//加载证书

func LoadRootCert(ctx contractapi.TransactionContextInterface) (cert x509.Certificate, err error) {
	bytes, err := ctx.GetStub().GetState(rootCertID)
	err = json.Unmarshal(bytes, &cert)
	log.Println("load Root Cert:" + string(bytes))
	return
}

func (s *RootCAContract) GetRootCertBytes(ctx contractapi.TransactionContextInterface) (string, error) {
	log.Println("start func GetRootCert")
	bytes, err := ctx.GetStub().GetState(rootCertID)
	return string(bytes), err
}

// 初始化 上传

func (s *RootCAContract) Init(ctx contractapi.TransactionContextInterface) error {
	log.Println("start Init function")
	err := s.AddRootCertBytes(ctx)
	if err != nil {
		return fmt.Errorf("failed to load root certificate: %w", err)
	}

	err = s.AddRootKeyBytes(ctx)
	if err != nil {
		return fmt.Errorf("failed to load root key: %w", err)
	}

	log.Println("Init function Successfully")
	return nil
}

// 根证书上链

func (s *RootCAContract) AddRootCertBytes(ctx contractapi.TransactionContextInterface) error {
	return ctx.GetStub().PutState(rootCertID, rootCertBytes)
}

// 根密钥字节数组上链接

func (s *RootCAContract) AddRootKeyBytes(ctx contractapi.TransactionContextInterface) error {
	return ctx.GetStub().PutState(rootCertKey, keyBytes)
}

// 中间证书

// 验证中间证书

// 撤销证书

func (s *RootCAContract) RevocationCert(ctx contractapi.TransactionContextInterface, id int) error {

	return nil
}

func (s *RootCAContract) GetAllElem(ctx contractapi.TransactionContextInterface) error {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return err
	}
	defer resultsIterator.Close()
	for resultsIterator.HasNext() {
		kv, err := resultsIterator.Next()
		if err != nil {
			return err
		}
		log.Println(kv.Key + ":" + string(kv.Value))
	}
	return nil
}
func main() {
	log.Println("============start chaincode ============")
	contract := RootCAContract{}
	caChaincode, err := contractapi.NewChaincode(&contract)
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err := caChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
	log.Println("start RootCA chaincode Successfully!")
	err = InitLedger()
	if err != nil {
		log.Panicf("Error Init chaincode: %v", err)
	}
	//caChaincode.DefaultContract = "InitRootCert"
	log.Println("Init RootCA chaincode Successfully!")
}
