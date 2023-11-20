package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGen(t *testing.T) {
	GenRsaKey(1024)
}

func TestSignService(t *testing.T) {
	priKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(priKey)
	marshalPKCS1PublicKey := x509.MarshalPKCS1PublicKey(&priKey.PublicKey)
	// pem 编码 公钥
	memoryPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   marshalPKCS1PublicKey,
	})
	_ = string(memoryPublicKey)
	memoryPrivateKey := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalPKCS1PrivateKey,
	})
	privateKey := string(memoryPrivateKey)
	if err != nil {
		t.Error(err)
	}
	sign, err := SignService(SignValue, []byte(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(priKey.PublicKey, SignValue, string(sign))
	if err != nil {
		t.Fatal(err)
	}
}
