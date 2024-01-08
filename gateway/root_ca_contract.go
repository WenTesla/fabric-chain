package gateway

import (
	"fmt"
	"github.com/hyperledger/fabric-gateway/pkg/client"
)

var CAContract = InitCA()

func Sign(contract *client.Contract) {
	transaction, err := contract.SubmitTransaction("GetAllElem")
	if err != nil {

	}
	fmt.Printf("%v", transaction)
}
