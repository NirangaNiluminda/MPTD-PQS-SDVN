package main

import (
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-samples/trajectory-chaincode/chaincode"
)

func main() {
	trajectoryChaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating trajectory chaincode: %v", err)
	}

	// CCAAS mode: if CHAINCODE_SERVER_ADDRESS is set, start as an external gRPC server.
	// Standard mode (default): connect back to the peer via shim.Start().
	if addr := os.Getenv("CHAINCODE_SERVER_ADDRESS"); addr != "" {
		server := &shim.ChaincodeServer{
			CCID:    os.Getenv("CHAINCODE_ID"),
			Address: addr,
			CC:      trajectoryChaincode,
			TLSProps: shim.TLSProperties{
				Disabled: true,
			},
		}
		log.Printf("Starting trajectory chaincode in CCAAS mode at %s", addr)
		if err := server.Start(); err != nil {
			log.Panicf("Error starting trajectory chaincode server: %v", err)
		}
	} else {
		// Standard peer-managed mode — the peer launches the binary and communicates via stdio.
		log.Print("Starting trajectory chaincode in standard (peer-managed) mode")
		if err := trajectoryChaincode.Start(); err != nil {
			log.Panicf("Error starting trajectory chaincode: %v", err)
		}
	}
}
