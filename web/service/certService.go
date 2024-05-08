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
	return bytes, handleError(err)
}

// 注册证书

func RegisterCertService(userId string, csr []byte) ([]byte, error) {
	bytes, err := intermediateCertContract.SubmitTransaction("RequestCert", userId, string(csr))
	return bytes, handleError(err)
}

// 撤销中间证书

func RevokeIntermediateService(id string) ([]byte, error) {
	bytes, err := rootCAContract.SubmitTransaction("DeleteCert", id)
	return bytes, handleError(err)
}

// 批准中间证书

func ApproveCertService(id string) ([]byte, error) {
	bytes, err := intermediateCertContract.SubmitTransaction("IssuerCert", id)
	return bytes, handleError(err)
}

// 撤销终端证书

func RevokeCertService(id string) ([]byte, error) {
	bytes, err := intermediateCertContract.SubmitTransaction("RevokeCert", id)
	return bytes, handleError(err)
}

func DeleteCertService(id string) ([]byte, error) {
	bytes, err := intermediateCertContract.SubmitTransaction("Delete", id)
	return bytes, handleError(err)
}

// 查看
func MyCertService(id string) ([]byte, error) {
	bytes, err := intermediateCertContract.EvaluateTransaction("CertInfoByUserId", id)
	return bytes, handleError(err)
}

// 查询全部中间证书

func CertAllService() ([]byte, error) {
	bytes, err := rootCAContract.EvaluateTransaction("GetAllElem")
	return bytes, handleError(err)
}

// 验证证书

func VerityCertService(cert string) (bool, error) {
	// 后端先检验
	if _, err := parseX509Cert([]byte(cert)); err != nil {
		return false, err
	}
	bytes, err := intermediateCertContract.SubmitTransaction("VerityCert", cert)
	if err != nil {
		return false, fmt.Errorf("证书错误%v", handleError(err))
	}
	if string(bytes) != "True" {
		return false, fmt.Errorf("该证书不在区块链上")
	}
	return true, nil
}

// 查询中间证书

func AllCertService() ([]byte, error) {
	result, err := intermediateCertContract.EvaluateTransaction("GetAllCerts")
	return result, handleError(err)
}

// 解析服务

func ParseCertService(certBytes []byte) (*x509.Certificate, error) {
	return parseX509Cert(certBytes)
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
	bytes, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, pri)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   bytes,
	}), nil
}

func RegisterCsrService(subject pkix.Name, dns, emails []string, pki []byte) ([]byte, error) {
	// 如果pki未提供,自己生成
	if pki == nil {
		var key, _ = rsa.GenerateKey(rand.Reader, 2048)
		return CreateCsr(subject, dns, emails, key)
	}
	key, err := parsePrivateKey(pki)
	if err != nil {
		return nil, err
	}
	return CreateCsr(subject, dns, emails, key)
}

// 加载公私密钥

func parsePrivateKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("密钥对格式错误，为%s", block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
