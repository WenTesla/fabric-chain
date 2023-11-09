package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestUserContract_Init2(t *testing.T) {
	InitContract()
}

func TestUserContract_Init(t *testing.T) {
	err := QueryUsers(UserContract)
	println(err)
}
func TestCreateUser(t *testing.T) {

}
func GenRsaKey(bits int) (privateKey, publicKey string) {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(priKey)
	marshalPKCS1PublicKey := x509.MarshalPKCS1PublicKey(&priKey.PublicKey)

	privateKey = string(marshalPKCS1PrivateKey)
	publicKey = string(marshalPKCS1PublicKey)
	return
}
func Test_con(t *testing.T) {
	transaction, err := UserContract.SubmitTransaction("ReadUser", "1")
	if err != nil {
		panic(err)
	}
	formatJSON := FormatJSON(transaction)
	fmt.Printf("%v", formatJSON)
}

func Test_Query(t *testing.T) {
	user, err := QueryUser(UserContract, "100")
	fmt.Println(user)
	fmt.Println(err)
}

func TestInitConfigContract(t *testing.T) {
	contract := InitConfigContract("mychannel", "cert")
	println(contract)
}
