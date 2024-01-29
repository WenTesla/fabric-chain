package gateway

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os"
	"path"
	"time"
)

const (
	// msp的ID
	mspID = "Org1MSP"
	// 基础路径
	//cryptoPath = "../../test-network/organizations/peerOrganizations/org1.example.com"
	cryptoPath = "/root/fabric/fabric-chain/test-network/organizations/peerOrganizations/org1.example.com"
	// 证书的路径
	certPath = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	// 密钥的路径
	keyPath = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	// tls的证书路径
	tlsCertPath = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	// peer一个节点的url
	peerEndpoint = "localhost:7051"
	// 网关的peer域名
	gatewayPeer = "peer0.org1.example.com"
)

// newGrpcConnection creates a gRPC connection to the gateway server.
// 新连接
func newGrpcConnection() *grpc.ClientConn {
	// 加载证书
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)
	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}
	return connection
}

// 加载证书
func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newIdentity creates a client identity for this gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}
	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}
	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}
	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}
	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}
	return sign
}

// Format JSON data

func FormatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}

// 初始化合约

func InitContract() *client.Contract {
	// channel 名称
	channelName := "mychannel"
	// 链码名称
	chaincodeName := "basic"
	// The gRPC client connection should be shared by all gateway connections to this endpoint
	// 创建 grpc 连接
	clientConnection := newGrpcConnection()
	//
	defer clientConnection.Close()

	id := newIdentity()

	sign := newSign()

	// Create a gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	//

	contract := network.GetContract(chaincodeName)
	return contract
}

func InitUserContract() *client.Contract {
	// channel 名称
	channelName := "mychannel"
	// 链码名称
	chaincodeName := "user"
	// The gRPC client connection should be shared by all gateway connections to this endpoint
	// 创建 grpc 连接
	clientConnection := newGrpcConnection()
	id := newIdentity()
	sign := newSign()
	// Create a gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	//defer gw.Close()

	network := gw.GetNetwork(channelName)
	//

	contract := network.GetContract(chaincodeName)
	println("开始启动智能合约")
	// 开始执行
	println("开始执行Init程序")
	return contract
}

func InitCA() *client.Contract {
	// channel 名称
	channelName := "mychannel"
	// 链码名称
	chaincodeName := "RootCA"
	// The gRPC client connection should be shared by all gateway connections to this endpoint
	// 创建 grpc 连接
	clientConnection := newGrpcConnection()
	id := newIdentity()
	sign := newSign()
	// Create a gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)
	println("开始启动智能合约")
	// 开始执行
	println("开始执行Init程序")
	return contract
}

//初始化链接

func InitConfigContract(channelName, chaincodeName string) *client.Contract {
	// The gRPC client connection should be shared by all gateway connections to this endpoint
	// 创建 grpc 连接
	clientConnection := newGrpcConnection()
	//defer clientConnection.Close()
	id := newIdentity()
	sign := newSign()
	// Create a gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	//defer gw.Close()
	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)
	return contract
}
