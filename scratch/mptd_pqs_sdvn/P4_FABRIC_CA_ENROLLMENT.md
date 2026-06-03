# P4 — Fabric-CA Per-Node Enrollment (Leased Identity Pool)

> **Status:** in progress (started 2026-06-03).
> **Paper basis:** §3.5.5 Algorithm 7 SC-Register — *"each vehicle vᵢ or RSU rⱼ
> submits its identity, public key, and LKH leaf key hash directly to the
> blockchain"* (vehicles submit as Fabric clients, NOT relayed by RSUs).
> **Design decision #1 (locked, see `project_sc_register_decisions.md`):**
> run Fabric-CA; vehicles enroll at boot to obtain an MSP x509 cert.

This file is the authoritative, plain-English record of *why* P4 is built the
way it is, so a future reader (or future me) doesn't have to reverse-engineer it
from the daemon and shell scripts. Read this before touching enrollment code.

---

## 1. What problem P4 solves

**Before P4 (TASK ② as shipped):** the gateway daemon
(`fabric_gateway_daemon/main.go`) holds a **single static identity** —
`User1@org1.example.com`, loaded once at boot. All 21 NS-3 nodes
(16 vehicles + 4 RSUs + 1 controller) submit SC-Register transactions through
that **one shared** Fabric identity.

- The on-chain `RegistrationRecord.PublicKey` *is* per-node (an app-level arg),
  but the **Fabric submitter** — the MSP creator on the transaction — is shared.
- That contradicts Algorithm 7's intent that each vehicle is itself a Fabric
  client submitting *its own* identity.

**After P4:** each node submits under **its own** Fabric-CA-enrolled x509 MSP
identity, so the transaction creator is per-node. This makes on-chain
submissions attributable to a genuinely-enrolled network participant, which is
the decentralization/accountability property the paper is demonstrating.

---

## 2. The decision: a *leased identity pool* (not unique-forever, not on-demand)

This was the pivotal design fork. Three candidate models were considered:

| Model | What it does | Verdict |
|---|---|---|
| **A — pre-enroll everyone at t=0** | enroll a fixed identity per node before sim start | ❌ breaks at SUMO scale (would enroll *thousands* in one blocking batch at bring-up) |
| **B — on-demand unique enroll** | each vehicle forks `fabric-ca-client` when it spawns, gets a unique forever-cert | ❌ CA latency (~100–300 ms) on the registration **critical path** mid-sim; unbounded cert + gateway-client sprawl |
| **C — leased identity pool** ✅ | pre-enroll a **bounded pool** at bring-up; vehicles **lease** a slot on spawn, **release** on departure | ✅ chosen |

### Why the pool wins (and why it's keyed to SUMO)

The current sim has 16 vehicles, all present from t=0 — *any* model works. The
pool was chosen because of where this project is **going**: SUMO traffic.

SUMO changes two things that break the naive models:

1. **Vehicles enter and leave mid-simulation** (each trip has a `depart` and
   `arrival` time). A vehicle entering at t=300 s should register at t=300 s.
2. **Total count ≫ concurrent count.** A scenario may have ~5,000 total trips
   over an hour but only ~200 vehicles on the road at any instant.

The leased pool handles both:

- **Enroll cost is bounded** by *pool size* (≈ peak concurrency), not total trip
  count, and is **front-loaded** at bring-up → **no CA latency on the mid-sim
  registration path**.
- **Lease-on-spawn / release-on-depart** matches SUMO's dynamic enter/leave, so
  "enrolls at boot" stays literally true per vehicle.
- **CA-admin authority stays out of the daemon** — the daemon only *loads*
  wallet certs; it never registers identities. (Model B would force the
  network-facing daemon to hold CA-admin powers — a security smell.)

### The pool size is a single knob → one mechanism, both regimes

`FABRIC_CA_POOL_SIZE` (env / config) is the only thing you tune:

- **Now (16 vehicles):** set pool ≥ vehicle count → **every vehicle gets a
  unique, dedicated identity.** Behaviourally identical to the strict
  "unique-per-vehicle" reading of Algorithm 7 — fully paper-faithful.
- **Later (SUMO, thousands):** set pool = peak concurrency (e.g. 256) →
  vehicles lease/reuse slots. Scales to any trip count without code changes.

Same code path. You change one number. That is the reason the pool was built
**now**, even though 16 static vehicles don't strictly need it — it's the
version that won't need rewriting when SUMO lands.

### Realism bonus (not a shortcut)

A leased identity pool is the **real-world V2X model**. IEEE 1609.2 / SCMS
vehicles draw from **pseudonym certificate pools** precisely because permanent
per-vehicle certs don't scale (and harm privacy). So the pool is *more* faithful
to deployed V2X PKI than unique-forever certs — pool reuse is a feature of the
domain, not a simulation compromise.

**Accountability note:** per-vehicle attribution comes from the role-prefixed
`VEH_<nid>` ID + app-level public key carried in the chaincode args (the
authoritative on-chain identity), while the leased MSP cert proves a legitimately
enrolled participant submitted it. When pool ≥ vehicle count these coincide
1:1; under reuse they are deliberately decoupled, exactly as pseudonym pools do.

---

## 3. Architecture (three pieces)

```
                 ┌────────────────────── bring-up (once) ──────────────────────┐
                 │  network.sh up ... -ca   →  ca_org1 @ localhost:7054         │
                 │  enroll_pool.sh          →  wallet/  (N pool + RSU/CTRL MSPs)│
                 └──────────────────────────────────────────────────────────────┘
                                            │ loads certs by name
                                            ▼
 NS-3 (11_blockchain_setup)  ──"id":"VEH_3"──►  fabric_gateway_daemon
   lease table: vid → pool slot                  map[identityName]→*client.Contract
   (lease on spawn, free on depart)              (lazy build, shared grpc conn)
   06c stamps leased identity on request         absent "id" → User1 fallback
```

### 3a. `enroll_pool.sh` (new, sibling of `explorer_fix.sh`)
Registers + enrolls, against `ca-org1` @ `https://localhost:7054`:
- `N` pool client identities: `pool0 … pool{N-1}` (id.type `client`).
- the fixed infra identities: one per RSU (`RSU_0..3`) and the controller
  (`CTRL_0`) — these are NOT leased, they're stable for the whole run.

Each enrollment writes an MSP dir (`signcerts/` + `keystore/`) into a wallet
root, mirroring the test-network's `registerEnroll.sh` conventions (same
`--caname`, same `--tls.certfiles` org CA cert). Idempotent: re-running skips
already-enrolled identities.

> Wallet root default: `<test-network>/organizations/peerOrganizations/
> org1.example.com/users/_mptd_pool/` so it sits next to the existing User1/Admin
> MSPs and inherits the same `config.yaml` NodeOU layout.

### 3b. Gateway daemon (`main.go`) — identity pool
- Replace the single global `contract` with `map[string]*client.Contract`,
  lazily populated and mutex-guarded. Each entry has its own
  `identity.X509Identity` + `identity.Sign` built from that identity's wallet
  MSP, but **shares the one grpc connection** (only the signer differs).
- Request JSON gains an **optional** `"id"` field (the identity name, e.g.
  `"VEH_3"` / `"RSU_0"` / `"pool7"`).
  - present → submit/evaluate under that identity (build+cache on first use).
  - **absent → `User1` fallback** (back-compat; existing callers unchanged).
- `User1` remains the daemon's boot/smoke-test identity so a daemon with no pool
  still works exactly as today.

### 3c. NS-3 wiring
- `11_blockchain_setup.h`: a small **lease table** (`vid → leased identity
  name`). On vehicle spawn/registration, lease a free pool slot; on departure
  (SUMO arrival), free it. RSUs/controller use their fixed names directly.
- `06c_blockchain_api.h`: the request builder stamps the caller's leased
  identity name into the new `"id"` field. Absent identity → empty → daemon
  uses User1 (so non-P4 code paths and the `skip_blockchain` path are untouched).

---

## 4. Operational notes

- **Docker native (NOT Docker Desktop).** The whole project runs on native
  Docker. P4 needs the CA-enabled network: `network.sh up createChannel -ca …`
  brings up `ca_org1` @ `localhost:7054` (+ `ca_org2`@8054, `ca_orderer`@9054).
  Ports are identical under both Docker runtimes, so no code change — but the CA
  **containers must be up** before `enroll_pool.sh` runs.
- **CA endpoint / creds** (from test-network defaults):
  - org1 CA: `https://localhost:7054`, caname `ca-org1`, admin `admin:adminpw`.
  - TLS cert: `<test-network>/organizations/fabric-ca/org1/ca-cert.pem`.
- **Fallback contract preserved:** if the daemon/socket is absent, NS-3 falls
  back to `fabric_invoke.sh` (User1, peer CLI) exactly as before P4.

---

## 5. What P4 does NOT do (scope honesty)

- **Does not fix the Hyperledger Explorer `priv_sk` papercut.** That is
  Explorer's *own* connection profile reading `Admin@org1`'s keystore under a
  hardcoded filename — a different consumer entirely. `explorer_fix.sh` remains
  the fix for that, and must still be re-run after any crypto regen.
- **Does not change the chaincode.** SC-Register's on-chain logic, the 2f+1
  endorsement check, and the `RegistrationRecord` schema are unchanged. P4 only
  changes *which Fabric identity signs the submitting transaction*.
- **Does not implement per-org split.** All pool/infra identities enroll under
  **Org1MSP**. Multi-org vehicle distribution is out of scope (not required by
  the paper's single-SDVN-domain model).

---

## 6. Quick reference

| Thing | Value |
|---|---|
| Pool size knob | `FABRIC_CA_POOL_SIZE` (default = node count → unique identities) |
| Wallet root | `…/users/_mptd_pool/` under org1 peerOrganizations |
| Request id field | `"id":"<identityName>"` (optional; absent → User1) |
| CA endpoint | `https://localhost:7054` caname `ca-org1` |
| Network bring-up | `network.sh up createChannel -ca` (native Docker) |
| Enroll script | `scratch/mptd_pqs_sdvn/enroll_pool.sh` |
| Daemon | `scratch/mptd_pqs_sdvn/fabric_gateway_daemon/main.go` |
