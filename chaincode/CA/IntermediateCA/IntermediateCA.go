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
	// 包含的字节数组 csr或者cert 有点问题
	Bytes string `json:"certBytes"`
	// 证书的hash值
	CertHashValue string `json:"certHashValue"`
	// 所拥有的证书的用户的Id
	UserId string `json:"userId"`
	// 状态
	Status int `json:"status"`
	// 颁发者的Id
	IssuerId string `json:"issuerId"`
}

type CertInfo struct {
	// 证书的主键
	CertId string `json:"certId"`
	// 版本号
	Version int `json:"version"`
	// 开始时间
	BeginDate string `json:"beginDate"`
	// 结束时间
	EndDate string `json:"endDate"`
	// subject
	Subject string `json:"subject"`
	// 颁发者
	Issuer string `json:"issuer"`
	// 包含的字节数组 csr或者cert 有点问题
	Bytes string `json:"certBytes"`
	// 证书的hash值
	CertHashValue string `json:"certHashValue"`
	// 所拥有的证书的用户的Id
	UserId string `json:"userId"`
	// 状态
	Status int `json:"status"`
	// 颁发者Id
	// 颁发者的Id
	IssuerId string `json:"issuerId"`
}

type HistoryQueryResult struct {
	Record    *CertInfo `json:"cert"`
	TxId      string    `json:"txId"`
	Timestamp time.Time `json:"timestamp"`
	IsDelete  bool      `json:"isDelete"`
}

// 状态
const (
	reviewing = iota // 审核中
	approved         // 已批准
	revoked          // 撤销
	rejected  = -1
)

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

func (I *IntermediateCAContract) RequestCert(ctx contractapi.TransactionContextInterface, userId, csr string) (int64, error) {
	// 查询用户Id是否存在
	exists, err := I.UserExists(ctx, userId)
	log.Printf("该用户在区块链上%v", exists)
	if err != nil || !exists {
		return 0, fmt.Errorf("该用户Id不在区块链%s\n错误:%v", userId, err)
	}
	request, err := pareCsr([]byte(csr))
	if err != nil {
		return 0, err
	}
	fmt.Sprintf("subject:%s", request.Subject)
	if err != nil {
		return 0, err
	}
	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
	var cert = Certs{
		CertId:        strconv.FormatInt(txTimestamp.GetSeconds(), 10),
		Version:       request.Version,
		BeginDate:     txTimestamp.AsTime(),
		EndDate:       txTimestamp.AsTime().AddDate(1, 0, 0),
		Subject:       request.Subject,
		Issuer:        pkix.Name{},
		Bytes:         (csr),
		CertHashValue: fmt.Sprintf("%x", sha256.Sum256([]byte(csr))),
		UserId:        userId,
		Status:        0,
	}
	log.Printf("证书信息为%v", cert)
	certBytes, err := json.Marshal(cert)
	if err != nil {
		return 0, err
	}
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	return timestamp.GetSeconds(), ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), certBytes)
}

// 用户向中间CA请求证书 用户Id，csr 保存上区块链上

//func (I *IntermediateCAContract) Request(ctx contractapi.TransactionContextInterface, userId, csr string) (int64, error) {
//	// 查询用户Id是否存在
//	exists, err := I.UserExists(ctx, userId)
//	log.Printf("该用户在区块链上%v", exists)
//	if err != nil || !exists {
//		return 0, fmt.Errorf("该用户Id不在区块链%s\n错误:%v", userId, err)
//	}
//	request, err := pareCsr([]byte(csr))
//	if err != nil {
//		return 0, err
//	}
//	//log.Printf("CSR为%v", request)
//	log.Printf("CSR的Subject：%s", request.Subject)
//	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()
//	var cert = Certs{
//		CertId:        strconv.FormatInt(txTimestamp.GetSeconds(), 10),
//		Version:       request.Version,
//		BeginDate:     txTimestamp.AsTime(),
//		EndDate:       txTimestamp.AsTime().AddDate(0, 1, 0),
//		Subject:       request.Subject,
//		Issuer:        pkix.Name{},
//		Bytes:         (csr),
//		CertHashValue: fmt.Sprintf("%x", sha256.Sum256([]byte(csr))),
//		UserId:        userId,
//		Status:        0,
//	}
//	log.Printf("证书信息为%v", cert)
//	certBytes, err := json.Marshal(cert)
//	if err != nil {
//		return 0, err
//	}
//	timestamp, _ := ctx.GetStub().GetTxTimestamp()
//	return timestamp.GetSeconds(), ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), certBytes)
//}

// 向根CA调用中间证书来颁发

func (*IntermediateCAContract) ReadIntermediateCert(ctx contractapi.TransactionContextInterface, id string) ([]byte, error) {
	args := [][]byte{[]byte("GetCert"), []byte(id)}
	return ctx.GetStub().InvokeChaincode("RootCA", args, "").Payload, nil
}

// 向根CA调用中间证书对应的私钥

func (*IntermediateCAContract) ReadIntermediateKey(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	args := [][]byte{[]byte("GetKey"), []byte("11")}
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

// 颁发证书 需要中间证书的私钥

func (I *IntermediateCAContract) IssuerCert(ctx contractapi.TransactionContextInterface, id, userId, issuerId, InterCertId, pri string) error {
	// 提取中间证书
	certBytes, _ := I.ReadIntermediateCert(ctx, InterCertId)
	log.Printf("x509的内容:%v", certBytes)
	// 解析中间证书
	x509Cert, err := parseX509Cert(certBytes)
	if err != nil {
		return fmt.Errorf("解析中间失败%v", err)
	}
	log.Printf("x509Cert的颁发者:%s", x509Cert.Issuer)
	// 提取中间证书对应的私钥
	publicKey, err := GetPublicKey(ctx, userId)
	if err != nil {
		return fmt.Errorf("获取公钥失败%v", err)
	}
	// 添加中间证书
	//log.Printf("证书信息:%v", *x509Cert)
	// 提取证书的csr
	state, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var cert = Certs{}
	json.Unmarshal(state, &cert)
	//log.Printf("证书%v", cert)
	// 如果证书已批准，则报错
	if cert.Status != reviewing {
		return fmt.Errorf("该证书不在审核状态！")
	}
	// 解析要签名的证书 错误
	csr, err := pareCsr([]byte(cert.Bytes))
	if err != nil {
		return fmt.Errorf("解析证书失败%v", err)
	}
	// 将csr转为证书
	certificate := conveyCertificateRequestToCertificate(csr)
	// 获取时间戳 并且赋值
	timestamp, _ := ctx.GetStub().GetTxTimestamp()
	// 序列号
	parseInt, _ := strconv.ParseInt(id, 10, 64)
	certificate.SerialNumber = big.NewInt(parseInt)
	certificate.NotBefore = time.Unix(timestamp.GetSeconds(), 0)
	certificate.NotAfter = time.Unix(timestamp.GetSeconds(), 0).AddDate(1, 0, 0)
	log.Printf("父证书%v", *certificate)
	// 获取中间证书的私钥
	privateKey, err := parsePrivateKey([]byte(pri))
	if err != nil {
		return fmt.Errorf("获取私钥失败%v", err)
	}
	log.Printf("开始创建证书")
	// 创建证书
	createCertificate, err := x509.CreateCertificate(rand.Reader, certificate, x509Cert, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败%v", err)
	}
	// pem编码
	//log.Printf("创建证书成功,cert字节为:%s", createCertificate)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   createCertificate,
	})
	log.Printf("pem证书为%s\n", pemBytes)
	// 改变证书状态并存入
	cert.CertId = strconv.FormatInt(timestamp.GetSeconds(), 10)
	cert.Status = approved
	cert.Bytes = string(pemBytes)
	cert.CertHashValue = fmt.Sprintf("%x", sha256.Sum256(pemBytes))
	cert.BeginDate = timestamp.AsTime()
	cert.EndDate = timestamp.AsTime().AddDate(1, 0, 0)
	cert.Issuer = x509Cert.Subject
	cert.IssuerId = issuerId
	cert.Version = certificate.Version
	marshal, _ := json.Marshal(cert)
	// 删除证书Id
	ctx.GetStub().DelState(id)
	return ctx.GetStub().PutState(strconv.FormatInt(timestamp.GetSeconds(), 10), marshal)
}

// 获得所有证书信息 错误

func (I *IntermediateCAContract) GetAllCerts(ctx contractapi.TransactionContextInterface) ([]CertInfo, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	var certs []CertInfo
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert Certs
		json.Unmarshal(queryResponse.GetValue(), &cert)
		var certInfo = CertInfo{
			CertId:        cert.CertId,
			Version:       cert.Version,
			BeginDate:     strconv.FormatInt(cert.BeginDate.Unix(), 10),
			EndDate:       strconv.FormatInt(cert.EndDate.Unix(), 10),
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			Bytes:         cert.Bytes,
			CertHashValue: cert.CertHashValue,
			UserId:        cert.UserId,
			Status:        cert.Status,
			IssuerId:      cert.IssuerId,
		}
		//log.Printf("certInfo:%v\n", certInfo)
		certs = append(certs, certInfo)
	}
	//log.Printf("返回certs对象:%v", certs)
	return certs, nil
}

// 撤销证书(软删除)

func (I *IntermediateCAContract) RevokeCert(ctx contractapi.TransactionContextInterface, id string) error {
	// 调用证书
	state, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	var cert Certs
	if err = json.Unmarshal(state, &cert); err != nil {
		return fmt.Errorf("json反序列化失败: %v", err)
	}
	cert.Status = revoked
	state, _ = json.Marshal(cert)
	log.Printf("改后的世界状态:%s", state)
	return ctx.GetStub().PutState(id, state)
}

// 删除证书

func (I *IntermediateCAContract) Delete(ctx contractapi.TransactionContextInterface, id string) error {
	log.Printf("证书的id为%s", id)
	return ctx.GetStub().DelState(id)
}

// 验证终端证书

func (I *IntermediateCAContract) VerityCert(ctx contractapi.TransactionContextInterface, certBytes string) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "false", err
	}
	defer resultsIterator.Close()
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "false", err
		}
		var cert Certs
		json.Unmarshal(queryResponse.GetValue(), &cert)
		if cert.Status == revoked {
			return "false", fmt.Errorf("该证书已被撤销")
		}
		if cert.Status == rejected {
			return "false", fmt.Errorf("该证书已拒绝")
		}
		log.Printf("%s", bytes.Equal([]byte(certBytes), []byte(cert.Bytes)))
		if certBytes == cert.Bytes {
			log.Printf("cert:%s", cert.Bytes)
			log.Printf("Bytes:%s", certBytes)
			return "true", nil
		}
		// 比较hash值
		if cert.CertHashValue == fmt.Sprintf("%x", sha256.Sum256([]byte(certBytes))) {
			log.Printf("该证书在区块链上%s", cert.CertId)
			return "true", nil
		}
		// 比较Id

	}
	return "false", fmt.Errorf("该证书不在区块链上！")
}

// 查看该用户id对应的证书

func (I *IntermediateCAContract) CertUserId(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "false", err
	}
	defer resultsIterator.Close()
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "false", err
		}
		var cert Certs
		json.Unmarshal(queryResponse.GetValue(), &cert)
		if cert.UserId == id {
			return cert.Bytes, nil
		}
	}
	return "", fmt.Errorf("该用户id未注册证书")
}

// 根据用户Id查看证书对应的信息

func (I *IntermediateCAContract) CertInfoByUserId(ctx contractapi.TransactionContextInterface, id string) ([]*CertInfo, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	var certs []*CertInfo
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert Certs
		json.Unmarshal(queryResponse.GetValue(), &cert)
		var certInfo = CertInfo{
			CertId:        cert.CertId,
			Version:       cert.Version,
			BeginDate:     strconv.FormatInt(cert.BeginDate.Unix(), 10),
			EndDate:       strconv.FormatInt(cert.EndDate.Unix(), 10),
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			Bytes:         cert.Bytes,
			CertHashValue: cert.CertHashValue,
			UserId:        cert.UserId,
			Status:        cert.Status,
			IssuerId:      cert.IssuerId,
		}
		if certInfo.UserId == id {
			certs = append(certs, &certInfo)
		}
	}
	return certs, nil
}

// 查看某个证书的历史

func (I *IntermediateCAContract) CertHistory(ctx contractapi.TransactionContextInterface, id string) ([]HistoryQueryResult, error) {
	resultsIterator, _ := ctx.GetStub().GetHistoryForKey(id)
	defer resultsIterator.Close()
	var records []HistoryQueryResult
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var cert CertInfo
		if len(response.Value) > 0 {
			err = json.Unmarshal(response.Value, &cert)
			if err != nil {
				return nil, err
			}
		}
		timestamp := response.Timestamp.AsTime()
		if err != nil {
			return nil, err
		}
		record := HistoryQueryResult{
			TxId:      response.TxId,
			Timestamp: timestamp,
			Record:    &cert,
			IsDelete:  response.IsDelete,
		}
		records = append(records, record)
	}
	return records, nil
}

// 加载x509证书

func parseX509Cert(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("x509证书加载失败,其格式为%s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// 加载公私密钥

func parsePrivateKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("密钥对格式错误，为%s", block.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}
	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pri := pkcs8PrivateKey.(type) {
	case *rsa.PrivateKey:
		return pri, nil
	}
	return nil, fmt.Errorf("无法解析RSA公钥: %v", err)
}

// 解析csr

func pareCsr(bytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("csr解析错误，类型为%s", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// 将Request转为Cert

func conveyCertificateRequestToCertificate(certificateRequest *x509.CertificateRequest) *x509.Certificate {
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
		Version:                     3,
		SerialNumber:                nil,
		Issuer:                      pkix.Name{},
		Subject:                     certificateRequest.Subject,
		NotBefore:                   time.Time{},
		NotAfter:                    time.Time{},
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		Extensions:                  certificateRequest.Extensions,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnhandledCriticalExtensions: nil,
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       true,  //
		IsCA:                        false, //
		MaxPathLen:                  0,     //
		MaxPathLenZero:              false,
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
	return &certificate
}

// 调用用户的公钥

func GetPublicKey(ctx contractapi.TransactionContextInterface, id string) (*rsa.PublicKey, error) {
	args := [][]byte{[]byte("GetPublicKey"), []byte(id)}
	response := ctx.GetStub().InvokeChaincode("user", args, "")
	log.Printf("获取的公钥数据:%s", response.Payload)
	return parseRSAPubKey(string(response.GetPayload()))
}
func parseRSAPubKey(bytes string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(bytes))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing PUBLIC KEY")
	}
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
