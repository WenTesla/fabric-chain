package gateway

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"
)

var contract = InitConfigContract("mychannel", "RootCA")

func TestInitConfigContract(t *testing.T) {
	contract := InitConfigContract("mychannel", "RootCA")
	_, err := contract.SubmitTransaction("Init")
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnect(t *testing.T) {
	contract := InitConfigContract("mychannel", "RootCA")
	if contract == nil {
		t.Fatal()
	}
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
	//log.Printf("%s",)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, key)
	if err != nil {
	}
	_, err = json.Marshal(csr)
	keyBytes, _ := json.Marshal(key.PublicKey)
	bytes, _ := json.Marshal(cert)
	certbytes, err := contract.SubmitTransaction("SignIntermediateCert", string(bytes), string(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%s", certbytes)

}

func TestPem(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICzDCCAbQCAQAwcDELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAlRKMQswCQYDVQQH\nDAJUSjELMAkGA1UECgwCVEoxDjAMBgNVBAsMBWJvd2VuMQ4wDAYDVQQDDAVib3dl\nbjEaMBgGCSqGSIb3DQEJARYLNDU2QDE2My5jb20wggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQC8IgTeTGVBebT6paVxzUVHOxy3GF/sDunuB7a6GhGPJyQ4\n8UqD01LacsNHhYoyaM+ZwBaFTood3WaSjZwL8NBdvgtF0qk8h9Qq6uZugUACkvII\nD5+qhihYuJ9fZiCqjpqx39D7cCPWsTHPjXN/Iew1lViQgSh9gDCnRjSyYTWIvHW0\nuNz+9yi61Wl22sNl0PP3EbywD9t85UwpXr/PaH6IGWyREe7jgFAVVlymiqtg/UQ0\napE5XYkgjwVODCbPTNV0nwqq+O6F1opzsCbVu/hnRDN3NVTNIXGFqOffKrLPgA+F\nVom+SgUkTjWl+fga2ULx0+fNqGngX3vUQ3cUwG9zAgMBAAGgFzAVBgkqhkiG9w0B\nCQcxCAwGMTIzNDU2MA0GCSqGSIb3DQEBCwUAA4IBAQBMY71+IQuV8a41v0foCOOK\nYaUrPJZeE0sGhaTWWoI0W1R9782rAsAF+0lRdsWAPlFt9o9M3MEmRtiQlWR8St74\n2PFy6f9Tjhc4vLSA7xGiZYd2qauw6zsGubl4MM1Bk3PMNhEP8l/FliQ7pbFnbk+M\nUrmy43gHOHT87pDJsk8GByEikWFgwHabPFbE+ayGYH6zi2ECFiw/+vhS4tN1q5E2\n1Ji0DzJe7I09rsAbgjkoaXlBdq0gvTBRFlp6iPrjCxC3zggccer9Ef2c54F2dFB5\nDo0AGPoYMI+65KPfRIytBq9ixsEDyG5zqL2jZ2JtIPI+8Raesln2pDQqXq7pdY9/\n-----END CERTIFICATE REQUEST-----"))

	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	println(block.Type)
}
func TestPub(t *testing.T) {
	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pR3EYb61Oo5f+f1Djmn\nv6TzApqjnUFsiF89HrTia6QtFt/7YdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd6\n04xdV8HnHO2e139Pg7pu2ZGDFHiVrAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3o\nrCxbjetHqgfnmKJgZPbO7vW+bGUJ9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11l\nCNXKmzbLPvQnRA0wB0a9z96Qn7gmmL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTm\nkGHT75Naeg6GXgghY1ceK5JdH+FoOoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8h\nQwIDAQAB\n-----END PUBLIC KEY-----"))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal()
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *dsa.PublicKey:
		fmt.Println("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	case ed25519.PublicKey:
		fmt.Println("pub is of type Ed25519:", pub)
	default:
		panic("unknown type of public key")
	}
}
func Test_Issue(t *testing.T) {
	csr := []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICuTCCAaECAQAwdDELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUhVQkVJMQswCQYD\nVQQHDAJYWTENMAsGA1UECgwEQ0FVQzENMAsGA1UECwwEQ0FVQzEOMAwGA1UEAwwF\nYm93ZW4xGjAYBgkqhkiG9w0BCQEWCzEyM0AxNjMuY29tMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEA0pR3EYb61Oo5f+f1Djmnv6TzApqjnUFsiF89HrTi\na6QtFt/7YdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd604xdV8HnHO2e139Pg7pu\n2ZGDFHiVrAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3orCxbjetHqgfnmKJgZPbO\n7vW+bGUJ9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11lCNXKmzbLPvQnRA0wB0a9\nz96Qn7gmmL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTmkGHT75Naeg6GXgghY1ce\nK5JdH+FoOoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8hQwIDAQABoAAwDQYJKoZI\nhvcNAQELBQADggEBADBbM1t2ZKTzxlEVUOUEowzO9bJYmPzpeap+MsI8q5P8yvNZ\n2BP8L62VZhs0mUI2CzdCtiFOWI4icLT3FVxgDWnQq0jnDpAvZMzTB2BAhTN090kq\nbCQmjrQy1hq8GUkq3o8rGuhp10o1wSiX1hLOPORL+8uAOq8fwtnSfslvfW+ohe+M\n5gn++jWbxmbWb9cW2tlGy4WXTeHQbRtFYtau33mlxeVDXHJZN7T4zERYDUZVJdzC\nGvJwp756WmDXv5tB8qdBDMBc86tKwnaShDGWWYq3qpwvb8OYw77DByh/IAp083Uy\n2H3mc9TKr7G5fr3Kx+uduxEGRCMaExzl+0laBU8=\n-----END CERTIFICATE REQUEST-----")
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pR3EYb61Oo5f+f1Djmn\nv6TzApqjnUFsiF89HrTia6QtFt/7YdCrbbg23a3MY5qrkHJPNvR4wJ8QXhjmUNd6\n04xdV8HnHO2e139Pg7pu2ZGDFHiVrAu2YvirzzAnZpTzPK5hdQ0LjHTsvyV2Qa3o\nrCxbjetHqgfnmKJgZPbO7vW+bGUJ9Jy57oZ5lD9ZsNehOYCYEA0bs2XaC9BSV11l\nCNXKmzbLPvQnRA0wB0a9z96Qn7gmmL7qm49TKfbJoCxvX7ytCFQBhlgBCsgXOjTm\nkGHT75Naeg6GXgghY1ceK5JdH+FoOoixAYljQGum0T2QtEBTR7rh4PqRipAmzd8h\nQwIDAQAB\n-----END PUBLIC KEY-----")

	transaction, err := InitConfigContract("mychannel", "RootCA").SubmitTransaction("IssueIntermediateCert", string(csr), string(pub))
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%s", transaction)
}

func Test_Hello(t *testing.T) {
	transaction, err := InitConfigContract("mychannel", "RootCA").SubmitTransaction("Hello")
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%s", transaction)
}

func Test_Invoke(t *testing.T) {
	bytes, err := InitConfigContract("mychannel", "RootCA").SubmitTransaction("Test")
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%s", bytes)
}
