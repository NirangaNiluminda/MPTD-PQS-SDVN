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
	"sync"
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

	// P4 — per-node Fabric-CA identity pool (see P4_FABRIC_CA_ENROLLMENT.md).
	// walletPath is the root produced by enroll_pool.sh; it holds one
	// <name>/msp/ per enrolled identity (pool0.., rsu0.., ctrl0..). A request
	// carrying "id":"<name>" is submitted under that identity; absent "id"
	// falls back to the default User1 identity (certPath/keyPath above), so
	// pre-P4 callers are unaffected.
	walletPath string

	// Phase 1C — chaincode-event subscription. The daemon tails Fabric events
	// matching `eventsAllow` into `eventsPath` (append-only JSONL). NS-3 reads
	// this file to drive cross-RSU LKH rekey on SCRevoke without each RSU
	// needing its own gateway client (Invariant 1 preserved: the daemon is
	// process-local, no controller relay).
	eventsPath  string
	eventsAllow []string
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
	// Allowlist is comma-separated; defaults cover every event the chaincode
	// currently emits. Override via FABRIC_GW_EVENTS_ALLOW="SCRevoke" etc.
	allowRaw := envOr("FABRIC_GW_EVENTS_ALLOW",
		"SCRevoke,TrustLow,CPDetectFlag,ControllerReassign,RSURevoke,RSUDemoted,RSUPromoted,RSUProbationHold")
	allow := []string{}
	for _, s := range splitCSV(allowRaw) {
		if s != "" {
			allow = append(allow, s)
		}
	}
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
		eventsPath:    envOr("FABRIC_GW_EVENTS_PATH", "/tmp/mptd_fabric_events.jsonl"),
		eventsAllow:   allow,
		walletPath:    envOr("FABRIC_GW_WALLET", crypto+"/users/_mptd_pool"),
	}
}

// splitCSV is a tiny strings.Split substitute that trims spaces — avoids
// pulling in the strings package for one call.
func splitCSV(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			// trim ASCII spaces
			lo, hi := 0, len(tok)
			for lo < hi && (tok[lo] == ' ' || tok[lo] == '\t') {
				lo++
			}
			for hi > lo && (tok[hi-1] == ' ' || tok[hi-1] == '\t') {
				hi--
			}
			out = append(out, tok[lo:hi])
			start = i + 1
		}
	}
	return out
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
// P4 — per-node Fabric-CA identity pool
//
// The Fabric Gateway SDK binds ONE signing identity at client.Connect time, so
// "submit as identity X" means "use the gateway connected with X's signer". We
// keep a lazily-populated map of identityName → gateway/contract, each backed by
// that identity's wallet MSP but SHARING the single grpc connection (only the
// signer differs). The default User1 identity is pre-seeded under the name
// defaultIdentity so requests with no "id" resolve without touching the wallet.
//
// Concurrency: contractFor is mutex-guarded on first build; the returned
// *client.Contract is itself concurrency-safe (multiple goroutines may submit),
// matching the daemon's existing no-serialize design.
// ─────────────────────────────────────────────────────────────────────────────

const defaultIdentity = "User1"

type idPool struct {
	mu        sync.Mutex
	conn      *grpc.ClientConn
	mspID     string
	walletDir string
	channel   string
	ccname    string
	gateways  map[string]*client.Gateway  // kept alive so contracts stay valid
	contracts map[string]*client.Contract // identityName → contract
}

func newIDPool(conn *grpc.ClientConn, cfg config) *idPool {
	return &idPool{
		conn:      conn,
		mspID:     cfg.mspID,
		walletDir: cfg.walletPath,
		channel:   cfg.channelName,
		ccname:    cfg.chaincodeName,
		gateways:  map[string]*client.Gateway{},
		contracts: map[string]*client.Contract{},
	}
}

// put pre-seeds an already-built gateway/contract under name (used for User1).
func (p *idPool) put(name string, gw *client.Gateway, c *client.Contract) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gateways[name] = gw
	p.contracts[name] = c
}

// gatewayFromMSP builds a gateway bound to the identity whose MSP lives at
// <walletDir>/<name>/msp (signcerts + keystore), sharing the pool's grpc conn.
func (p *idPool) gatewayFromMSP(name string) (*client.Gateway, error) {
	mspDir := path.Join(p.walletDir, name, "msp")
	certPEM, err := readFirstFile(path.Join(mspDir, "signcerts"))
	if err != nil {
		return nil, fmt.Errorf("read signcert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signcert: %w", err)
	}
	id, err := identity.NewX509Identity(p.mspID, cert)
	if err != nil {
		return nil, fmt.Errorf("x509 identity: %w", err)
	}
	keyPEM, err := readFirstFile(path.Join(mspDir, "keystore"))
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(p.conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(15*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
}

// contractFor returns the contract for identityName, lazily loading it from the
// wallet on first use. A miss surfaces as an error so the caller can reject the
// request rather than silently fall back to the wrong identity.
func (p *idPool) contractFor(name string) (*client.Contract, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.contracts[name]; ok {
		return c, nil
	}
	gw, err := p.gatewayFromMSP(name)
	if err != nil {
		return nil, fmt.Errorf("load identity %q from wallet: %w", name, err)
	}
	contract := gw.GetNetwork(p.channel).GetContract(p.ccname)
	p.gateways[name] = gw
	p.contracts[name] = contract
	log.Printf("[fabric-gw] identity loaded from wallet: %s", name)
	return contract, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire protocol
// ─────────────────────────────────────────────────────────────────────────────

type request struct {
	Action   string   `json:"action"`   // "invoke" | "query"
	Function string   `json:"function"` // chaincode function name
	Args     []string `json:"args"`     // string args (Args[0] is implicitly fn)

	// P4 — identity selector. Names an enrolled wallet identity (pool0../rsu0..
	// /ctrl0..) to submit under. Empty → defaultIdentity (User1), so pre-P4
	// callers and the skip_blockchain path are unaffected.
	Id string `json:"id,omitempty"`

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

func handleConn(c net.Conn, pool *idPool) {
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

	// P4 — resolve the submitting identity. Empty id → User1 (back-compat).
	idName := req.Id
	if idName == "" {
		idName = defaultIdentity
	}
	contract, err := pool.contractFor(idName)
	if err != nil {
		writeErr(wr, fmt.Sprintf("identity %q: %v", idName, err))
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
// Phase 1C — chaincode event subscriber
//
// Paper §3.5.5 Eq 3.58: when ≥2f+1 RSU votes commit on SCRevokeVote, the
// chaincode emits "SCRevoke". All RSUs in the network need to learn about
// this so they can rekey their LKH ring (Eq 3.21–3.25). Without an event
// channel, only the *voting* RSUs see the revocation — remote RSUs keep the
// stale key and the attacker can still talk to them. TASK1_DELIVERABLE.md
// flags this as Known Gap #1.
//
// We tail the gateway's ChaincodeEvents stream into a JSONL file. NS-3 RSU
// code polls the file on a Simulator schedule (cheap — append-only seq scan)
// and dispatches to per-RSU LKH rekey. The file approach (vs streaming
// socket) keeps the C++ side trivial and survives daemon restarts without
// reconnection state — the NS-3 reader just keeps a file offset.
//
// Event-record wire format (one JSON line per accepted event):
//   {"ts":"2026-05-31T10:00:00.123Z","name":"SCRevoke",
//    "tx":"abc123…","blk":42,"payload":"{\"vehicleID\":\"5\",…}"}
//
// The file is truncated on daemon startup — each sim run gets a fresh log.
// ─────────────────────────────────────────────────────────────────────────────

type eventRecord struct {
	Ts      string `json:"ts"`
	Name    string `json:"name"`
	Tx      string `json:"tx"`
	Blk     uint64 `json:"blk"`
	Payload string `json:"payload"`
}

func runEventListener(ctx context.Context, network *client.Network,
	chaincodeName, outPath string, allow []string) {

	allowSet := make(map[string]struct{}, len(allow))
	for _, n := range allow {
		allowSet[n] = struct{}{}
	}
	allowAll := len(allowSet) == 0

	// Truncate-on-startup: each daemon run = fresh event log, so NS-3 readers
	// start at offset 0 with no risk of replaying stale revocations.
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("[fabric-gw] events: open %s: %v (listener disabled)", outPath, err)
		return
	}
	defer f.Close()
	log.Printf("[fabric-gw] events: writing %s allow=%v", outPath, allow)

	// Reconnect loop: ChaincodeEvents returns a channel that closes on stream
	// error; we retry with bounded backoff so peer restarts during a long sim
	// don't kill the listener permanently. No checkpointing yet — start from
	// "now" each retry, which is correct for our LKH-rekey use case (a missed
	// revocation is repaired when the RSU next sees a beacon from the vehicle).
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		events, err := network.ChaincodeEvents(ctx, chaincodeName)
		if err != nil {
			log.Printf("[fabric-gw] events: subscribe %s: %v (retry in %s)",
				chaincodeName, err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second // reset on successful subscribe

		for ev := range events {
			if !allowAll {
				if _, ok := allowSet[ev.EventName]; !ok {
					continue
				}
			}
			rec := eventRecord{
				Ts:      time.Now().UTC().Format(time.RFC3339Nano),
				Name:    ev.EventName,
				Tx:      ev.TransactionID,
				Blk:     ev.BlockNumber,
				Payload: string(ev.Payload),
			}
			line, err := json.Marshal(&rec)
			if err != nil {
				log.Printf("[fabric-gw] events: marshal %s: %v", ev.EventName, err)
				continue
			}
			line = append(line, '\n')
			if _, err := f.Write(line); err != nil {
				log.Printf("[fabric-gw] events: write %s: %v", outPath, err)
				continue
			}
			// fsync so NS-3 readers see the line as soon as it lands — important
			// for the SCRevoke→rekey latency budget. The cost is a single fdatasync
			// per event, which is fine at the few-events-per-second rate we expect.
			_ = f.Sync()
			log.Printf("[fabric-gw] events: %s tx=%.10s blk=%d", ev.EventName, ev.TransactionID, ev.BlockNumber)
		}
		// channel closed — gateway lost the stream; loop will resubscribe
		log.Printf("[fabric-gw] events: stream closed; resubscribing in %s", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
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

	// P4 — identity pool. Pre-seed the default User1 identity (already built
	// above) so requests with no "id" resolve instantly; per-node identities
	// (pool0../rsu0../ctrl0..) load lazily from the wallet on first use.
	pool := newIDPool(conn, cfg)
	pool.put(defaultIdentity, gw, contract)
	log.Printf("[fabric-gw] identity pool ready; wallet=%s default=%s", cfg.walletPath, defaultIdentity)

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

	// Phase 1C — start chaincode-event listener. Background lifetime matches
	// the daemon's; on SIGINT/SIGTERM the deferred listener.Close + os.Exit
	// path tears it down.
	evCtx, evCancel := context.WithCancel(context.Background())
	defer evCancel()
	go runEventListener(evCtx, network, cfg.chaincodeName,
		cfg.eventsPath, cfg.eventsAllow)

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
		go handleConn(c, pool)
	}
}
