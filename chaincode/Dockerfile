# go 1.24: required by the ML-DSA-87 ledger verifier dep (cloudflare/circl
# v1.6.4 declares go 1.24.0). Build the default ML-DSA-87 verifier; for the
# classical ECDSA P-256 ablation pass --build-arg LEDGER_TAGS=ledger_ecdsa.
FROM golang:1.24-alpine AS build

ARG LEDGER_TAGS=""
WORKDIR /go/src/github.com/hyperledger/fabric-samples/trajectory-chaincode
COPY . .

RUN go build -tags "${LEDGER_TAGS}" -o /chaincode .

FROM alpine:latest

COPY --from=build /chaincode /chaincode

EXPOSE 9999
CMD ["/chaincode"]
