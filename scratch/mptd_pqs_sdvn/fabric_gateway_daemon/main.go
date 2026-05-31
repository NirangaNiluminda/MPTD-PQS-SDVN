// fabric_gateway_daemon — long-lived Hyperledger Fabric Gateway proxy
// =============================================================================
// Replaces the per-call `fabric_invoke.sh` shell shim with a persistent gRPC
// gateway connection that NS-3 can call over a Unix socket. Eliminates the
// 1–2s per-call `peer chaincode invoke` fork-exec-tls-handshake overhead.
//
// Paper invariants satisfied:
//   • Invariant 1 — RSU→Fabric direct. The daemon runs co-located with the
//     RSU process; the Unix socket is process-local. No controller relay,
//     no centralized proxy across the network.
//   • Invariant 6 — no centralized bottleneck. A daemon per RSU node would
//     give true per-RSU gateway isolation; the current single-daemon mode
//     mirrors the legacy `fabric_invoke.sh` behaviour and is fine for the
//     SDN-controller-as-peer simulation we run today.
//
// Wire protocol:
//   Each accept() takes ONE JSON line in, writes ONE JSON line back, closes.
//
//   Request:
//     {"action": "invoke" | "query",
//      "function": "<chaincode-fn>",
//      "args":     ["arg1", "arg2", ...]}
//
//   Response:
//     {"ok": true,  "payload": "<chaincode-return-bytes-as-utf8>"}
//   or
//     {"ok": false, "error":   "<error-message>"}
//
// Bring-up:
//   Defaults match the fabric-samples test-network layout. Overrides via env:
//     FABRIC_GW_SOCKET=/tmp/mptd_fabric.sock
//     FABRIC_GW_MSP_ID=Org1MSP
//     FABRIC_GW_CRYPTO_PATH=/home/niranga/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com
//     FABRIC_GW_PEER_ENDPOINT=localhost:7051
//     FABRIC_GW_PEER=peer0.org1.example.com
//     FABRIC_GW_CHANNEL=mychannel
//     FABRIC_GW_CHAINCODE=trajectory
//
// Fallback contract: if the socket file does not exist, the NS-3 client falls
// back to `fabric_invoke.sh`, so removing the daemon = automatic legacy mode.
// =============================================================================
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (env-overridable, defaults match fabric-samples test-network)
// ─────────────────────────────────────────────────────────────────────────────

type config struct {
	socketPath    string
	mspID         string
	cryptoPath    string
	certPath      string
	keyPath       string
	tlsCertPath   string
	peerEndpoint  string
	gatewayPeer   string
	channelName   string
	chaincodeName string
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	crypto := envOr("FABRIC_GW_CRYPTO_PATH",
		"/home/niranga/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com")
	return config{
		socketPath:    envOr("FABRIC_GW_SOCKET", "/tmp/mptd_fabric.sock"),
		mspID:         envOr("FABRIC_GW_MSP_ID", "Org1MSP"),
		cryptoPath:    crypto,
		certPath:      crypto + "/users/User1@org1.example.com/msp/signcerts",
		keyPath:       crypto + "/users/User1@org1.example.com/msp/keystore",
		tlsCertPath:   crypto + "/peers/peer0.org1.example.com/tls/ca.crt",
		peerEndpoint:  envOr("FABRIC_GW_PEER_ENDPOINT", "dns:///localhost:7051"),
		gatewayPeer:   envOr("FABRIC_GW_PEER", "peer0.org1.example.com"),
		channelName:   envOr("FABRIC_GW_CHANNEL", "mychannel"),
		chaincodeName: envOr("FABRIC_GW_CHAINCODE", "trajectory"),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Gateway connection helpers (lifted from fabric-samples Go gateway sample)
// ─────────────────────────────────────────────────────────────────────────────

func newGrpcConnection(cfg config) (*grpc.ClientConn, error) {
	certificatePEM, err := os.ReadFile(cfg.tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("read TLS cert %s: %w", cfg.tlsCertPath, err)
	}
	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS cert: %w", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, cfg.gatewayPeer)
	return grpc.NewClient(cfg.peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
}

func newIdentity(cfg config) (*identity.X509Identity, error) {
	pem, err := readFirstFile(cfg.certPath)
	if err != nil {
		return nil, fmt.Errorf("read user cert dir %s: %w", cfg.certPath, err)
	}
	certificate, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("parse user cert: %w", err)
	}
	return identity.NewX509Identity(cfg.mspID, certificate)
}

func newSign(cfg config) (identity.Sign, error) {
	pem, err := readFirstFile(cfg.keyPath)
	if err != nil {
		return nil, fmt.Errorf("read user key dir %s: %w", cfg.keyPath, err)
	}
	privateKey, err := identity.PrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("parse user key: %w", err)
	}
	return identity.NewPrivateKeySign(privateKey)
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fileNames, err := dir.Readdirnames(1)
	if err != nil {
		return nil, err
	}
	if len(fileNames) == 0 {
		return nil, fmt.Errorf("%s is empty", dirPath)
	}
	return os.ReadFile(path.Join(dirPath, fileNames[0]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire protocol
// ─────────────────────────────────────────────────────────────────────────────

type request struct {
	Action   string   `json:"action"`   // "invoke" | "query"
	Function string   `json:"function"` // chaincode function name
	Args     []string `json:"args"`     // string args (Args[0] is implicitly fn)

	// FireAndForget — when true on an invoke, daemon writes {"ok":true}
	// immediately and submits in a detached goroutine. The caller can close
	// the connection and continue without waiting for the ~1s commit. Used
	// by the NS-3 lightweight beacon path (paper Invariant 3, T_b=100 ms)
	// so SUBM writes never stall the per-beacon loop.
	FireAndForget bool `json:"fire_and_forget,omitempty"`
}

type response struct {
	Ok      bool   `json:"ok"`
	Payload string `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

// The Fabric Gateway client's Contract.{Submit,Evaluate}Transaction are
// concurrency-safe per the fabric-gateway SDK contract — multiple goroutines
// can endorse/submit in parallel and the orderer handles ordering. We do NOT
// serialize here; doing so would defeat the whole point of switching off the
// shell shim (which serialized on fork-exec contention).

func handleConn(c net.Conn, contract *client.Contract) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	rd := bufio.NewReader(c)
	wr := bufio.NewWriter(c)
	defer wr.Flush()

	line, err := rd.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		writeErr(wr, fmt.Sprintf("read request: %v", err))
		return
	}
	if len(line) == 0 {
		writeErr(wr, "empty request")
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		writeErr(wr, fmt.Sprintf("parse json: %v", err))
		return
	}
	if req.Function == "" {
		writeErr(wr, "missing function")
		return
	}

	switch req.Action {
	case "invoke":
		if req.FireAndForget {
			// ACK first so the NS-3 caller unblocks immediately, then submit
			// in a detached goroutine. The submit error (if any) is logged
			// here — the caller has already moved on, by design.
			writeOk(wr, "")
			wr.Flush()
			go func(fn string, args []string) {
				if _, err := contract.SubmitTransaction(fn, args...); err != nil {
					log.Printf("[fabric-gw] fire-and-forget submit %s: %v", fn, err)
				}
			}(req.Function, append([]string(nil), req.Args...))
			return
		}
		payload, err := contract.SubmitTransaction(req.Function, req.Args...)
		if err != nil {
			writeErr(wr, fmt.Sprintf("submit %s: %v", req.Function, err))
			return
		}
		writeOk(wr, string(payload))
	case "query":
		payload, err := contract.EvaluateTransaction(req.Function, req.Args...)
		if err != nil {
			writeErr(wr, fmt.Sprintf("evaluate %s: %v", req.Function, err))
			return
		}
		writeOk(wr, string(payload))
	default:
		writeErr(wr, fmt.Sprintf("unknown action %q (expected invoke|query)", req.Action))
	}
}

func writeOk(w *bufio.Writer, payload string) {
	json.NewEncoder(w).Encode(response{Ok: true, Payload: payload})
}
func writeErr(w *bufio.Writer, msg string) {
	json.NewEncoder(w).Encode(response{Ok: false, Error: msg})
}

// ─────────────────────────────────────────────────────────────────────────────
// main — wire up, listen, accept loop
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()
	log.Printf("[fabric-gw] socket=%s mspID=%s peer=%s channel=%s ccname=%s",
		cfg.socketPath, cfg.mspID, cfg.peerEndpoint, cfg.channelName, cfg.chaincodeName)

	conn, err := newGrpcConnection(cfg)
	if err != nil {
		log.Fatalf("grpc connection: %v", err)
	}
	defer conn.Close()

	id, err := newIdentity(cfg)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	sign, err := newSign(cfg)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(15*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		log.Fatalf("gateway connect: %v", err)
	}
	defer gw.Close()

	network := gw.GetNetwork(cfg.channelName)
	contract := network.GetContract(cfg.chaincodeName)
	log.Printf("[fabric-gw] gateway connected; contract=%s/%s", cfg.channelName, cfg.chaincodeName)

	// Unix socket setup — clean stale socket if it exists, then chmod 660.
	_ = os.Remove(cfg.socketPath)
	listener, err := net.Listen("unix", cfg.socketPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", cfg.socketPath, err)
	}
	defer listener.Close()
	if err := os.Chmod(cfg.socketPath, 0660); err != nil {
		log.Printf("[fabric-gw] warning: chmod %s: %v", cfg.socketPath, err)
	}
	log.Printf("[fabric-gw] listening on %s", cfg.socketPath)

	// Signal handler — clean shutdown removes the socket so the NS-3 client
	// falls back to the shell shim transparently.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[fabric-gw] shutdown signal; removing socket")
		_ = os.Remove(cfg.socketPath)
		_ = listener.Close()
		os.Exit(0)
	}()

	// Quick connectivity smoke test — evaluate GetNetworkConfig at boot.
	smokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := contract.EvaluateWithContext(smokeCtx, "GetNetworkConfig"); err != nil {
		log.Printf("[fabric-gw] startup smoke FAILED: %v (daemon will still serve, but Fabric may be down)", err)
	} else {
		log.Printf("[fabric-gw] startup smoke OK (GetNetworkConfig evaluated)")
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			// Listener closed on shutdown — exit cleanly.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[fabric-gw] accept: %v", err)
			continue
		}
		go handleConn(c, contract)
	}
}
