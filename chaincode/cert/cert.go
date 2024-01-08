package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"log"
	"time"
)

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

var Cert = x509.Certificate{
	Raw:                         nil,
	RawTBSCertificate:           nil,
	RawSubjectPublicKeyInfo:     nil,
	RawSubject:                  nil,
	RawIssuer:                   nil,
	Signature:                   nil,
	SignatureAlgorithm:          0,
	PublicKeyAlgorithm:          0,
	PublicKey:                   nil,
	Version:                     0,
	SerialNumber:                nil,
	Issuer:                      pkix.Name{},
	Subject:                     pkix.Name{},
	NotBefore:                   time.Time{},
	NotAfter:                    time.Time{},
	KeyUsage:                    0,
	Extensions:                  nil,
	ExtraExtensions:             nil,
	UnhandledCriticalExtensions: nil,
	ExtKeyUsage:                 nil,
	UnknownExtKeyUsage:          nil,
	BasicConstraintsValid:       false,
	IsCA:                        false,
	MaxPathLen:                  0,
	MaxPathLenZero:              false,
	SubjectKeyId:                nil,
	AuthorityKeyId:              nil,
	OCSPServer:                  nil,
	IssuingCertificateURL:       nil,
	DNSNames:                    nil,
	EmailAddresses:              nil,
	IPAddresses:                 nil,
	URIs:                        nil,
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

// SmartContract provides functions for managing an user
type SmartContract struct {
	contractapi.Contract
}

func main() {
	userChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}
	if err = userChaincode.Start(); err != nil {
		log.Panicf("Error starting  chaincode: %v", err)
	}
	log.Printf("Chaincode deploy Successfully")
}
