# RSU Ring Key Generation — DKG (Eq 3.25 `dkg_trs` / Eq 3.26 `dkg_fhe`)

**Branch:** `feature/dkg-ring-keys` (off `master`). **Date:** 2026-06-30.
**Status:** code written on the laptop, **NOT compiled/verified here** — the
C++/OpenSSL EC build + selftest + NS-3 round-trip must be run on the HPC.

---

## 1. Why

The 2026-06 paper revision added a dedicated subsection *"RSU Ring Key
Generation via Distributed Key Generation (DKG)"*: TRS signing keys and FHE
key shares are generated **among the RSU ring + Cloud, with no single dealer
and no controller involvement**; the blockchain is the public bulletin board
for commitments (Eq `dkg_trs` 3.25, Eq `dkg_fhe` 3.26).

What the code did **before** this change:

| Key class | Before | Paper |
|---|---|---|
| Vehicle session keys `K_i` | RSU-local KDF | RSU-local ✅ (unchanged) |
| **TRS signing keys (Classical backend)** | **single trusted-dealer polynomial seeded from `K_ring`** (`06b1`) | DKG, no dealer ❌ |
| TRS signing keys (Dilithium backend) | independent per-signer ML-DSA keypairs | per-member, no shared secret — already aligned |
| FHE threshold shares | OpenFHE chained `MultipartyKeyGen` | multiparty DKG — already aligned |

The only literal **"trusted dealer"** was the Classical Shamir-Schnorr backend
(the RQ5/A4 baseline). That is what this change replaces.

## 2. What changed

### `06b1_trs_backend.h` — `ClassicalTrsBackend::generate_keys` (the real change)
Replaced the single dealer polynomial (seeded from `K_ring`) with a
**Joint-Feldman VSS DKG**:

1. Each of the `n` ring members samples its **own** degree-`(t-1)` polynomial
   `f_i` with **fresh CSPRNG** coefficients (`BN_rand_range`) — no shared seed,
   `K_ring` is no longer read here.
2. Each member broadcasts **Feldman commitments** `C_{i,k} = a_{i,k}·G`.
3. **Share verification**: for every contributor `i` and recipient `j`, check
   `f_i(j)·G == Σ_k j^k·C_{i,k}` (catches a corrupted contributor).
4. Final per-signer share `s_j = Σ_i f_i(j)`; group key `master_pk = Σ_i C_{i,0}
   = x·G`, where the group secret `x = Σ_i a_{i,0}` is **never assembled** at any
   single entity.

**Key property:** `(master_pk, {s_j}, {pk_j})` is algebraically the *same* `(t,n)`
Shamir sharing as the old dealer output, so **`partial_sign` / `aggregate` /
`verify_threshold` are unchanged** (`σ·G == H(m)·master_pk` still holds). Zero
downstream churn — CP-DETECT, PARR, the selftest, the blockchain submit path all
keep working.

### Comment / framing fixes (no behavioural change)
- `06b1` header + class summary: "sim-side trusted dealer" / `K_ring`-seed
  description → DKG description.
- `06b1` Dilithium backend: noted each RSU keypair is independent (no dealer).
- `06b2_fhe_backend.h`: noted the chained `MultipartyKeyGen` **is** the paper's
  FHE-DKG (Eq 3.26), no dealer/controller.
- `00_lkh_keys.h`: removed the stale quote *"managed by the SDN controller"*
  (that sentence was **deleted** from the paper); clarified the RSU-ring subtree
  now serves only as the SC-Register leaf commitment + FHE-share transport, and
  that TRS signing keys come from the DKG in `06b1`.

## 3. Honest faithfulness statement (for the report / viva)
- **Real:** per-member fresh randomness, Feldman commitments, verifiable share
  check, summed shares, group secret never materialised — genuine VSS DKG. No
  dealer, no controller, no central `K_ring` seed for the TRS keys.
- **Abstracted (in-process):** all `n` members run inside the one NS-3 process,
  and the commitment **publication to the blockchain bulletin board** +
  over-the-network share exchange are **not yet wired**. This is the *same*
  realism level as the OpenFHE multiparty FHE-DKG in `06b2` (also in-process).

## 4. HPC verification (REQUIRED — not done on the laptop)
1. Build NS-3 with the sim (`-lcrypto` already linked): `python3 waf build`.
2. Run the crypto selftest: `MPTD_CRYPTO_SELFTEST=1 python3 waf --run "mptd_pqs_sdvn ... --simTime=2"`
   → TRS-1/2 (key sizes, sign→aggregate→verify round-trip, wrong-ring rejection)
   must stay green for **both** Classical and Dilithium backends.
3. A live `--routing_algorithm=4` round-trip (register → submit-evidence →
   TRS verify) to confirm CP-DETECT / PARR unaffected.

## 5. Remaining DKG follow-up (over-the-network — needs the live Fabric layer)
- Publish each member's Feldman commitments to the chain as the **authenticated
  bulletin board**, and exchange shares over the RSU ring channel rather than
  in-process.
- Same for the Dilithium ring (publish `pk_j` on-chain) and the FHE shares.

## 6. One-liner to fold into `HPC_HANDOFF.md` (lives on `docs/hpc-handoff`)
> **DKG (branch `feature/dkg-ring-keys`):** Classical TRS now uses Joint-Feldman
> DKG (no dealer/`K_ring`); Dilithium + FHE were already multiparty. Build +
> selftest on HPC. Over-the-network exchange + on-chain commitment bulletin board
> still TODO. See `scratch/mptd_pqs_sdvn/DKG_RING_KEYS.md`.
