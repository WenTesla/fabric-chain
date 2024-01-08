package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestInit(t *testing.T) {
	transaction, err := CAContract.SubmitTransaction("InitRootCert")
	if err != nil {
		t.Fail()
	}
	println(transaction)
}
func TestGet(t *testing.T) {
	bytes, err := CAContract.SubmitTransaction("Init")
	if err != nil {
		t.Fatal(err)
	}
	println(bytes)
}
func TestSign(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

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
		Subject: pkix.Name{
			Organization: []string{"CAUC"},
			Country:      []string{"CN"},
			Province:     []string{"TJ"},
			Locality:     []string{"TJ"},
			CommonName:   "Inter CA",
		},
		Extensions:      nil,
		ExtraExtensions: nil,
		DNSNames:        nil,
		EmailAddresses:  nil,
		IPAddresses:     nil,
		URIs:            nil,
	}
	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(1555),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Province:           []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
			Organization:       []string{"JediLtd"},
			OrganizationalUnit: []string{"JediProxy"},
			CommonName:         "Jedi Inter CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, key)
	if err != nil {
	}
	_, err = json.Marshal(csr)
	keyBytes, err := json.Marshal(key.PublicKey)
	bytes, _ := json.Marshal(cert)
	certbytes, err := CAContract.SubmitTransaction("SignIntermediateCert", string(bytes), string(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	println(certbytes)
	parseCertificate, err := x509.ParseCertificate(certbytes)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v", parseCertificate)
}
