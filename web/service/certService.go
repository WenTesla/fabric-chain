package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"web/gateway"
)

var rootCAContract = gateway.InitConfigContract("mychannel", "RootCA")

var intermediateCertContract = gateway.InitConfigContract("mychannel", "MiddleCA")

// 中间证书注册

func IntermediateCertRegisterService(csr, pub string) ([]byte, error) {
	bytes, err := rootCAContract.SubmitTransaction("IssueIntermediateCert", csr, pub)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// 注册证书

func RegisterCertService(userId string, csr []byte) error {
	bytes, err := intermediateCertContract.SubmitTransaction("RequestCert", userId, string(csr))
	if err != nil {
		return err
	}
	fmt.Printf("%s", bytes)
	return nil
}

// 撤销中间证书

func RevokeIntermediateService(id string) ([]byte, error) {
	return rootCAContract.SubmitTransaction("DeleteCert", id)
}

// 批准中间证书

func ApproveCertService(id string) ([]byte, error) {
	return intermediateCertContract.SubmitTransaction("IssuerCert", id)
}

// 查询全部中间证书

func CertAllService() ([]byte, error) {
	return rootCAContract.SubmitTransaction("GetAllElem")
}

// 验证证书

func VerityCertService(cert string) (bool, error) {
	bytes, err := rootCAContract.SubmitTransaction("VerityCert", cert)
	if err != nil {
		return false, fmt.Errorf("证书错误%v", err)
	}
	if string(bytes) != "True" {
		return false, fmt.Errorf("证书错误")
	}
	return true, nil
}

// 查询中间证书

func AllCertService() ([]byte, error) {
	return intermediateCertContract.SubmitTransaction("GetAllCerts")
}

// 解析服务

func ParseCertService(certBytes []byte) (*x509.Certificate, error) {
	return parseX509Cert(certBytes)
}

type certInfo struct {
	// 序列号
	Id string
	// 主题信息

	// 签发者信息

}

// 解析x509证书的信息

func parseX509Cert(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pem证书加载失败,其格式为%s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// 创建csr
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
