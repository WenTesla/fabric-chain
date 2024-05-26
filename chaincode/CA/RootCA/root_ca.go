package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"math/big"
	"strconv"
	"time"
)

type RootCAContract struct {
	contractapi.Contract
}

// 中间证书

type inter struct {
	Key  string `json:"key"`  // 密钥
	Cert string `json:"cert"` // 证书
}

type CertInfo struct {
	Id        string `json:"id"`
	HashValue string `json:"hashValue"`
	Content   string `json:"content"`
	IssuerID  string `json:"issuerID"`
}

// 根私钥

var keyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0pR3EYb61Oo5f+f1Djmnv6TzApqjnUFsiF89HrTia6QtFt/7
YdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd604xdV8HnHO2e139Pg7pu2ZGDFHiV
rAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3orCxbjetHqgfnmKJgZPbO7vW+bGUJ
9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11lCNXKmzbLPvQnRA0wB0a9z96Qn7gm
mL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTmkGHT75Naeg6GXgghY1ceK5JdH+Fo
OoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8hQwIDAQABAoIBAQCK/OL59pVoIpCB
E6BzGyrVGxIqDdcf3Ca+e93jfpBTa7E2/+7zyL7dVFEiT6wvsc67MDeIliN9P3+W
G+koQpEXP/X8Dkd0mIHWyni5ATxY7eoOgOiI/dIL0QXVYnsfAgDpdE9u6oVM13/L
SfabsyV3Pm/PZBOQ7la2L7Zf7Wb34JigiZot7j6f5SxCgf+zTL7yC1nuph5OO8dP
QFndf4ZTaKf4XepRLnkTqsf4AGIGrIcL4jvaf+7t5WAInILvnzaAwq/8QGnwwGYh
zFsyq+ApYyeKlR5DWdYNEKr6/brAa96ehya4xJe4senCbFbz4xKdtNlHFq+YuN+h
I/pBKY2BAoGBAOtpALgHpWHHsRFfILXUURMt9Dzt9dp5t9SwHQrZNFkrAMjb/tg9
tVaa/tcgtt5RV+qsPO0Qn9hoKD0HQ96OZQ8mI4OjWG0ab8PVNNDDdo3qh+fcdSr6
mbqCWflUeFD9KIyg1/3l74i+edsasfu87D0bve9hsnAs3ryV+C1M6iiJAoGBAOT/
fw3wg77nUfMrhMy8rskj3ttJe4Ed4BSJ0T4hixPNpU8y8dx5Ny3TH7Olgag/O55H
UtcSQTL6IsdE2xgSMTSSdbHyWwpCRrN3d1veuI2k7ptc8zzYwBF2mqZO7OBqLBS1
Kp8G7mCSi4Q9RHqMYA9dkRLRoIcDRLybj8+ekrBrAoGAOKruIV610PPhC+16Ukrp
uVQ2lvQxWoYyWmCKnTHsCAryBWfv0N4J6O8mqWKWoq2yHCuZ/vchg1aPWSGGlOxy
J1Nm+Sk5AAp9HQcVz6s9vqvWS1omWlI470yxm/NZgyVtvWx6kgPnxWMUskmazp6L
v6oN7rH14krq0zrGoyEAvQECgYAcrFkuV6VHbBN4zUQtlpqUGOe4sXTDcAg0yiTn
ELAnZKKETi62mn7sP/lCN0EK3hAK+4dF4sVDKsrcBKUiWHTMzmHqTBxWJoJPym+p
kzOsmLA/x921CrbR+PXYSR2j4+dtGFoj22xRr0fE4R8H8Te99MtLffAJt8ENlLTn
HEXlzQKBgQCsCSkBXa4YF2k3Alsc3skTgK/KAvYr3bDBjoSGY+xrYJ7oipIeTbv6
+fYxIUrsiUgeRYPl7UxVKwtg0kJByVy3oEMMS7Csb5D6oUbormUjeVclAYoTatj7
j6p0JvXqXopuBchK2uazTT5beCPzCGy6NrmxRcrTHAeGNXi79cxTzw==
-----END RSA PRIVATE KEY-----
`)

// 根证书

var rootCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIDbzCCAlcCFD/oOgfjWvIj8iIwRumGUXK9yjy3MA0GCSqGSIb3DQEBCwUAMHQx
CzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVIVUJFSTELMAkGA1UEBwwCWFkxDTALBgNV
BAoMBENBVUMxDTALBgNVBAsMBENBVUMxDjAMBgNVBAMMBWJvd2VuMRowGAYJKoZI
hvcNAQkBFgsxMjNAMTYzLmNvbTAeFw0yNDAxMDEwNDEyMThaFw0zMzEyMjkwNDEy
MThaMHQxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVIVUJFSTELMAkGA1UEBwwCWFkx
DTALBgNVBAoMBENBVUMxDTALBgNVBAsMBENBVUMxDjAMBgNVBAMMBWJvd2VuMRow
GAYJKoZIhvcNAQkBFgsxMjNAMTYzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANKUdxGG+tTqOX/n9Q45p7+k8wKao51BbIhfPR604mukLRbf+2HQ
q224Nt2tzGOaq5ByTzb0eMCfEF4Y5lDXetOMXVfB5xztntd/T4O6btmRgxR4lawL
tmL4q88wJ2aU8zyuYXUNC4x07L8ldkGt6KwsW43rR6oH55iiYGT2zu71vmxlCfSc
ue6GeZQ/WbDXoTmAmBANG7Nl2gvQUlddZQjVyps2yz70J0QNMAdGvc/ekJ+4Jpi+
6puPUyn2yaAsb1+8rQhUAYZYAQrIFzo05pBh0++TWnoOhl4IIWNXHiuSXR/haDqI
sQGJY0BrptE9kLRAU0e64eD6kYqQJs3fIUMCAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAbdG7dk0WVDXrcKbp5B1hyMGI4qmHcwwFpr5nJup5PeNY0yJAcIDahuB4Lilg
dD1ZBjvNmYb1rn3Ynfo6PHTIwS20wbSIle5bbldyJC0qhdcyIzYNlg9hG5sT/qPd
tkfRxlmIGLB/iCPdQcTJBrnYzX0iRbikQz6U+IxERhfhMUBLAleG02lmknyOr7Fm
794NOlz+IDF03aRvrrNcYZSezlTyOkEAJFy6LitgMPE3/+VTJFWaBqaqT0p3UZNX
xrLwbE0TOeOZNO40rC1yG2FlpHYvRWvGCKaLNRRG+jxWmE7PUuhKNCFM1PxrihkH
y4Cpwt/jYOk/vmhDvxEj2Thr7g==
-----END CERTIFICATE-----
`)

// 根证书模板

var rootCsr = x509.Certificate{
	SerialNumber: big.NewInt(2024),
	Subject: pkix.Name{
		Organization:       []string{"CAUC"},
		OrganizationalUnit: []string{"CAUC"},
		Country:            []string{"CN"},
		Province:           []string{"TJ"},
		Locality:           []string{"TJ"},
		CommonName:         "Root CA", // 证书持有者通用名，需保持唯一，否则验证会失败
	},
	NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
	NotAfter:              time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
	BasicConstraintsValid: true, //为true表示IsCA/MaxPathLen/MaxPathLenZero有效，为false忽略这几个配置
	IsCA:                  true, // 是否为CA证书，CA证书可以为下级证书签证，为false代表是终端证书，不能继续签证，根证书和中级证书都应该为true
	MaxPathLen:            1,    // 表示证书链中可在此证书之后的非自颁发中级证书的最大层级，我们只需要1个中级证书就可以了，根证书设置为1，中级证书设置为0，那么中级证书就不能继续签署中级证书了。-1 表示未设置，且MaxPathLenZero == false && MaxPathLen == 0视为-1
	MaxPathLenZero:        false,
	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign, //支持签发和吊销中级证书
}

// 中间证书模板
var interCsr = &x509.Certificate{
	Version:      3,
	SerialNumber: big.NewInt(2024),
	Subject: pkix.Name{
		Country:            []string{"CN"},
		Province:           []string{"TJ"},
		Locality:           []string{"Shanghai"},
		Organization:       []string{"JediLtd"},
		OrganizationalUnit: []string{"JediProxy"},
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

// 根证书和密钥是否匹配

func InitLedger() error {
	// 是否匹配
	if _, err := tls.X509KeyPair(rootCertBytes, keyBytes); err != nil {
		return err
	}
	fmt.Println("根证书和密钥对匹配成功")
	return nil
}

// 加载pem证书

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

// 颁发中间证书(pem编码) csr包含 直接颁发 同时检测HASH值，防止重复上传

func (s *RootCAContract) IssueIntermediateCert(ctx contractapi.TransactionContextInterface, csrBytes, pri string) (string, error) {
	log.Println("开始执行IssueIntermediateCert")
	// 加载根证书的私钥
	RootKey, err := parseKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("私钥加载失败")
	}
	// 解析私钥
	//key, err := parseKey([]byte(pri))
	//if err != nil {
	//	return "", fmt.Errorf("私钥加载失败%v",err)
	//}
	//// 解析RSA公钥
	//pub, err := parseRSAPubKey(userId)
	//if err != nil {
	//	return "", fmt.Errorf("解析公钥失败%v", err)
	//}
	//pub, err := GetPublicKey(ctx, userId)
	if err != nil {
		return "", fmt.Errorf("解析公钥失败%v", err)
	}
	//log.Printf("pub:%v", *pub)
	// 解析csr请求
	certificateRequest, err := parseCertificateRequest(csrBytes)
	if err != nil {
		return "", fmt.Errorf("解析scr请求失败%v", err)
	}
	log.Printf("csr:%v\n", *certificateRequest)
	// 获取时间戳
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	log.Printf("当前交易的时间戳为%d", timestamp.GetSeconds())
	certificate := conveyCertificateRequestToCertificate(certificateRequest)
	// 将证书的ID赋予为时间戳
	certificate.SerialNumber = big.NewInt(timestamp.GetSeconds())
	// 赋值证书的时间
	certificate.NotBefore = time.Unix(timestamp.GetSeconds(), 0)
	certificate.NotAfter = time.Unix(timestamp.GetSeconds(), 0).AddDate(1, 0, 0)
	// Der编码的
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&certificate,
		&rootCsr,
		certificate.PublicKey,
		RootKey,
	)
	if err != nil {
		return "", fmt.Errorf("创建证书失败%v", err)
	}
	log.Printf("创建证书成功,cert字节为:%s", certBytes)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   certBytes,
	})
	log.Printf("pem证书为%s\n", pemBytes)
	//
	marshal, err := json.Marshal(CertInfo{
		Id:        strconv.FormatInt(timestamp.GetSeconds(), 10),
		HashValue: fmt.Sprintf("%x", sha256.Sum256([]byte(pemBytes))),
		Content:   string(pemBytes),
		IssuerID:  pri,
	})
	// 检测hash值
	//s.checkHash(ctx,)
	if err != nil {
		return "", err
	}
	// 将证书的hash值上链
	return string(pemBytes), ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), marshal)
}

// 解析CSR请求(pem格式)
// openssl cli: openssl req -in xxx.csr

func parseCertificateRequest(bytes string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(bytes))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// 解析pem公钥 返回RSA公钥

func parseRSAPubKey(bytes string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(bytes))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing PUBLIC KEY")
	}
	//pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	//if err != nil {
	//	return nil, err
	//}
	//switch pub := pub.(type) {
	//case *rsa.PublicKey:
	//	return pub, nil
	//default:
	//	return nil, fmt.Errorf("此公钥非RSA公钥")
	//}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return publicKey, nil
	}
	// 解析格式
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("无法解析RSA公钥: %v", err)
}

// 将Request转为Cert

func conveyCertificateRequestToCertificate(certificateRequest *x509.CertificateRequest) x509.Certificate {
	return x509.Certificate{
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
}

// 中间证书

// 验证中间证书的有效性

func (s *RootCAContract) VerityCert(ctx contractapi.TransactionContextInterface, certBytes string) (bool, error) {
	// 先检查证书合法性
	cert, err := parseX509Cert([]byte(certBytes))
	if err != nil {
		return false, err
	}
	// 检查是否为根证书
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.IsCA {
		return false, fmt.Errorf("此证书为根证书")
	}
	// 检查中间证书是否在库中
	exists, err := s.CertExists(ctx, cert.SerialNumber.String())
	if err != nil || exists == false {
		return false, fmt.Errorf("中间证书不在区块链上,其证书的序列号为%s", cert.SerialNumber)
	}
	log.Printf("中间证书在区块链上,其证书的序列号为%s", cert.SerialNumber)
	// 低级的API
	//if err = cert.CheckSignatureFrom(&rootCsr);err != nil {
	//	return false, fmt.Errorf("CheckSignatureFrom 失败%v", err)
	//}
	log.Printf("开始检查证书链")
	// 检查证书链
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootCertBytes)
	pool.AddCert(&rootCsr)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: nil,
	})
	fmt.Printf("%s", pool.Subjects())
	log.Printf("error:%v", err)
	return err == nil, err
}

// 撤销证书

func (s *RootCAContract) RevocationCert(ctx contractapi.TransactionContextInterface, id string) error {
	return s.DeleteCert(ctx, id)
}

// 查看所有中间证书

func (s *RootCAContract) GetAllElem(ctx contractapi.TransactionContextInterface) ([]CertInfo, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	//
	var certs []CertInfo
	for resultsIterator.HasNext() {
		kv, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert CertInfo
		json.Unmarshal(kv.GetValue(), &cert)
		// 添加
		certs = append(certs, cert)
		log.Println(kv.Key + ":" + string(kv.Value))
	}
	return certs, nil
}

// 根据Id判断cert是否存在

func (s *RootCAContract) CertExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	certJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return certJSON != nil, nil
}

// 根据ID删除cert

func (s *RootCAContract) DeleteCert(ctx contractapi.TransactionContextInterface, id string) error {
	// 判断是否存在
	exists, err := s.CertExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the cert %s does not exist", id)
	}
	return ctx.GetStub().DelState(id)
}

// 获取最新的中间证书

func (s *RootCAContract) GetNewCert(ctx contractapi.TransactionContextInterface) (string, error) {
	stateByRange, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "", err
	}
	defer stateByRange.Close()
	kv, err := stateByRange.Next()
	return string(kv.GetValue()), nil
}

// 查看是否有中间证书

func (s *RootCAContract) CheckIntermediateCert(ctx contractapi.TransactionContextInterface) error {
	stateByRange, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return err
	}
	defer stateByRange.Close()
	if !stateByRange.HasNext() {
		return fmt.Errorf("中间证书不存在，请注册中间证书")
	}
	return nil
}

// Id获取证书

func (s *RootCAContract) GetCert(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	state, _ := ctx.GetStub().GetState(id)
	var cert CertInfo
	json.Unmarshal(state, &cert)
	log.Printf("GetCert已被调用")
	return cert.Content, nil
}

// 检测HASH值

func (s *RootCAContract) checkHash(ctx contractapi.TransactionContextInterface, id string) bool {
	return false
}
func main() {
	log.Println("============start chaincode ============")
	if InitLedger() != nil {
		log.Panicf("Error Init chaincode: %v", InitLedger())
	}
	contract := RootCAContract{}
	caChaincode, err := contractapi.NewChaincode(&contract)
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err := caChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
	log.Println("start RootCA chaincode Successfully!")
}
