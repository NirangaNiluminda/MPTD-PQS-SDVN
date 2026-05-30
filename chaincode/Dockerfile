FROM golang:1.23-alpine AS build

WORKDIR /go/src/github.com/hyperledger/fabric-samples/trajectory-chaincode
COPY . .

RUN go build -o /chaincode .

FROM alpine:latest

COPY --from=build /chaincode /chaincode

EXPOSE 9999
CMD ["/chaincode"]
