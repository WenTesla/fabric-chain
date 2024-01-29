package service

import (
	"fmt"
	"web/gateway"
)

var certContract = gateway.InitConfigContract("mychannel", "RootCA")

// 证书注册

func CertRegisterService(csr, pub string) ([]byte, error) {
	bytes, err := certContract.SubmitTransaction("IssueIntermediateCert", csr, pub)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// 查询全部证书

func CertAllService() ([]byte, error) {
	return certContract.SubmitTransaction("GetAllElem")
}

// 验证证书

func VerityCertService(cert string) (bool, error) {
	bytes, err := certContract.SubmitTransaction("VerityCert", cert)
	if err != nil {
		return false, fmt.Errorf("证书错误%v", err)
	}
	if string(bytes) != "True" {
		return false, fmt.Errorf("证书错误")
	}
	return true, nil
}
