package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"google.golang.org/grpc/status"
	"web/gateway"
)

var rootCAContract = gateway.InitConfigContract("mychannel", "RootCA")

var intermediateCertContract = gateway.InitConfigContract("mychannel", "MiddleCA")

// 中间证书注册

func IntermediateCertRegisterService(csr, pub string) ([]byte, error) {
	return rootCAContract.SubmitTransaction("IssueIntermediateCert", csr, pub)
}

// 注册证书

func RegisterCertService(userId string, csr []byte) ([]byte, error) {
	return intermediateCertContract.SubmitTransaction("RequestCert", userId, string(csr))
}

// 撤销中间证书

func RevokeIntermediateService(id string) ([]byte, error) {
	return rootCAContract.SubmitTransaction("DeleteCert", id)
}

// 批准中间证书

func ApproveCertService(id string) ([]byte, error) {
	return intermediateCertContract.SubmitTransaction("IssuerCert", id)
}

// 撤销终端证书

func RevokeCertService(id string) ([]byte, error) {
	return intermediateCertContract.SubmitTransaction("RevokeCert", id)
}

// 查询全部中间证书

func CertAllService() ([]byte, error) {
	return rootCAContract.SubmitTransaction("GetAllElem")
}

// 验证证书

func VerityCertService(cert string) (bool, error) {
	bytes, err := rootCAContract.SubmitTransaction("VerityCert", cert)
	if err != nil {
		return false, fmt.Errorf("证书错误%v", handleError(err))
	}
	if string(bytes) != "True" {
		return false, fmt.Errorf("证书错误")
	}
	return true, nil
}

// 查询中间证书

func AllCertService() ([]byte, error) {
	result, err := intermediateCertContract.EvaluateTransaction("GetAllCerts")
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			panic(fmt.Errorf("transaction %s failed to endorse with gRPC status %v: %w", err.TransactionID, status.Code(err), err))
		case *client.SubmitError:
			panic(fmt.Errorf("transaction %s failed to submit to the orderer with gRPC status %v: %w", err.TransactionID, status.Code(err), err))
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				panic(fmt.Errorf("timeout waiting for transaction %s commit status: %w", err.TransactionID, err))
			} else {
				panic(fmt.Errorf("transaction %s failed to obtain commit status with gRPC status %v: %w", err.TransactionID, status.Code(err), err))
			}
		case *client.CommitError:
			panic(fmt.Errorf("transaction %s failed to commit with status %d: %w", err.TransactionID, int32(err.Code), err))

		default:
			panic(err)
		}
	}
	return result, err
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

// 编码
