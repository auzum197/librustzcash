# Draft: Shielded Note Disclosure

Status: Draft. Candidate for the unsigned disclosure encoding left open in ZIP 311. Covers the Sapling, Orchard and Ironwood pools.

## Terminology

- Disclosure: a string that lets any holder decrypt and check a set of shielded outputs of one transaction.
- Discloser: the party that produces an Item. It is the sender (with `ovk`) or the receiver (with `ivk`) of the output.
- Verifier: the party that checks a Disclosure against the transaction bytes.
- Item: the per-output part of a Disclosure.
- Disclosure set: a file of Disclosures for several transactions.
- Address space: the set of addresses one key tree derives for a pool family. Sapling is one address space. Orchard and Ironwood share another.

## Properties

A Verifier that accepts an Item obtains these guarantees. Each property cites the protocol-spec security requirements it depends on. Section numbers refer to the Zcash Protocol Specification.

- P1, note binding. The output at the stated index commits to `(g_d, pk_d, v, rcm)`, plus `(rho, psi)` for Orchard and Ironwood. Depends on computational binding (§4.1.8) of `NoteCommit^Sapling` (§5.4.8.2) and `NoteCommit^Orchard` (§5.4.8.4).
- P2, memo binding. One output yields one memo under verification. The note fields occupy the plaintext bytes before the memo. A second key that also decrypts `C_enc` changes those fields, and the commitment check then fails. Depends on the same requirements as P1.
- P3, scope. A holder learns `d`, `pk_d`, `v` and the memo of each listed output. Depends on IND-CCA2 security and key privacy of the in-band encryption scheme (§4.1.6) for the unlisted outputs, the PRF requirement on `PRF^expand` (§4.1.2), and the key agreement requirement (§4.1.5), which makes `ivk` infeasible to recover from `(g_d, pk_d)`. Two consequences follow from public transaction data:
  - Each disclosed `v`, with the bundle's public `valueBalance`, gives the net value of the unlisted spends and outputs of that bundle. When the bundle has no shielded spends and one other output, the holder learns that output's value.
  - A transaction author can reuse `rseed` or `esk` across outputs to one address. A holder of one such Item can then find and open the other outputs.
- P4, linkability. Items with equal `(address space, d, pk_d)` belong to one receiver address. Holders of several Disclosures can link them on that triple. Linkers MUST include the address space in the key: a Sapling and an Orchard `(d, pk_d)` can share bytes. All change and ZIP 318 migration outputs of an account go to one internal address per address space. Their Items link to each other. That no further link exists depends on Unlinkability of `DiversifyHash` (§5.4.1.6).
- P5, bearer. Any holder can verify and forward a Disclosure. A Disclosure is irrevocable once shared. Items compose freely: anyone can remove Items or merge Items for the same txid. A Disclosure carries no evidence that one party produced all its Items. Depends on no cryptographic requirement.
- P6, receivability. For types `0x02`, `0x03`, `0x04` and `0x06`, the owner of the `ivk` with `pk_d = [ivk] g_d` derives the same `K_enc` from `epk` and accepts the plaintext under the protocol's lead-byte rules. Type `0x05` lacks P6. Follows from verification steps 4 and 5 and from the correctness of `KA.Agree` (§4.1.5).

The Disclosure carries no evidence for the facts below. The Verifier obtains the first two from chain data. The last two stay unknown to the Verifier.

- Inclusion and depth. The block height also feeds the lead-byte check.
- Transaction validity: the zk-SNARKs and signatures.
- Spend status. Nullifier derivation needs `nk`, which stays with the wallet.
- Authorship. For types `0x02`, `0x03`, `0x05` and `0x06`, the sender and the receiver can each produce the same Item. Only the transaction author or a holder of the sender's `ovk` knows `esk` for a lead-byte-`0x01` note. A type `0x04` Item reveals that its Discloser is on the sender side.

### Adversaries that compute discrete logarithms

This section is informative. It considers an adversary, an efficient algorithm as in the protocol spec's security definitions, that can also compute discrete logarithms on Jubjub and Pallas, for example with a quantum computer. The requirements that P1 to P4 cite then fail. Type `0x06` keeps a hash-based bound on P1, given at the end of this section. This adversary obtains `ivk` from `pk_d = [ivk] g_d` and reads every note of that scope. An Item for a change or migration output exposes the internal scope. Transaction validity fails as well. A Disclosure stored today stays exposed to this adversary later. For type `0x06`, the `H^rcm` check of ZIP 2005 reduces a forged opening to a collision search, estimated at 2^127 evaluations classically and 2^85 with a quantum collision algorithm.

## Encoding

```
Disclosure = Bech32m(HRP, version || txid || Item*)
Item       = typecode || length || body
```

- `HRP` is `zdisc` (mainnet), `zdisctest` (testnet) or `zdiscregtest` (regtest). The HRP is the only network binding. Implementations use a Bech32m decoder without the 90-character limit, as ZIP 316 does. Register the three HRPs in SLIP-0173.
- `version` is one byte, `0x01`.
- `txid` is 32 bytes in internal byte order:
  - v4: SHA-256d of the raw transaction encoding (protocol spec §7.1.1).
  - v5: ZIP 244.
  - v6: ZIP 229, which adds `ironwood_digest_v6` to the ZIP 244 digest.
- `typecode` and `length` are CompactSize. `length` is the byte length of `body`.
- `index` is CompactSize. It is the position in the bundle that the typecode selects.

| Typecode | Bundle | Note plaintext lead byte | Body |
|---|---|---|---|
| `0x02` | Sapling outputs | `0x02` (ZIP 212) | `index \|\| pk_d \|\| rseed` |
| `0x03` | `vActionsOrchard` | `0x02` | `index \|\| pk_d \|\| rseed` |
| `0x04` | Sapling outputs | `0x01` (pre-ZIP 212), sender | `index \|\| pk_d \|\| esk` |
| `0x05` | Sapling outputs | `0x01` (pre-ZIP 212), receiver | `index \|\| pk_d \|\| K_enc` |
| `0x06` | `vActionsIronwood` | `0x03` (ZIP 2005) | `index \|\| pk_d \|\| rseed` |

Each body is 1 to 5 bytes of `index` plus 64 bytes. `d`, `v` and the memo come from decryption.

Typecodes `0xE0` to `0xFF` are MUST-understand. A Verifier skips any other unknown typecode and reports it.

The format has no free-text field. Nothing authenticates text outside the memo. Any holder could edit it, and a Verifier would show it next to verified data. ZIP 311 carries a message because its signature binds it. A Disclosure has no signature. Context such as an invoice number goes in the memo when the payment is made, or in the channel that carries the Disclosure.

### Canonical form

A decoder rejects the string when any rule below fails. Each Disclosure then has exactly one string.

- The string is all lowercase, and the Bech32m padding is at most 4 bits, all zero.
- Every CompactSize is minimal.
- For known typecodes, `length` equals the body size. No bytes follow the last Item.
- Items are strictly increasing by `(typecode, index)`.
- An output appears at most once. Uniqueness is keyed on `(bundle, index)`. Types `0x02`, `0x04` and `0x05` share the Sapling bundle.
- The Disclosure has at least one Item with a known typecode, and no Item with an unknown MUST-understand typecode.
- The Disclosure has at most 64 Items, and each body is at most 255 bytes.

## Disclosure sets

A Disclosure covers one transaction. A Disclosure set covers several. It is a UTF-8 text file with the extension `.zdisc`.

- Each line is one Disclosure in canonical form, and every line ends with LF.
- All lines use the same HRP.
- A txid appears on at most one line. Items for one transaction go into one Disclosure.
- The order of lines carries no meaning.

A Verifier checks each line on its own and reports the result per line. A set tells the Verifier that one party disclosed these transactions together. The Verifier learns the same from separate Disclosures sent together.

## Producing an Item

Types `0x02`, `0x03` and `0x06` need `rseed`.

- Receiver: trial-decrypt `C_enc` with `ivk` (the internal `ivk` for change) and read `rseed` from the plaintext.
- Sender: derive `ock` from `ovk`, decrypt `C_out` to get `(pk_d, esk)`, derive `K_enc` and decrypt `C_enc` to read `rseed`. This path requires that the transaction was built with an `ovk`. A transaction built with `ovk = ⊥` leaves only the receiver path.

Type `0x04` uses the sender path and takes `esk` from `C_out`. Type `0x05` uses the receiver path and takes `K_enc`. A sender produces `0x04` for a lead-byte-`0x01` note, since `0x04` gives P6.

Ironwood uses the Orchard key tree, addresses and viewing keys (ZIP 2005). A wallet produces type `0x03` and type `0x06` Items with the same Orchard `ivk` and `ovk`. The `use_qsk` flag changes how `rivk` is derived, and with it `ivk`. It has no effect on the Item or on verification.

A Discloser MUST check, before it emits an Item, that the Item's secret (`rseed`, `esk` or `K_enc`) is unique among the outputs it knows at that address. It warns the user when the secret repeats.

A Discloser SHOULD ask for explicit confirmation before it discloses an internal-scope output (change or migration). The confirmation states that the Item links to every other change Item of the account (P4) and exposes the internal scope to a discrete-log adversary.

## Verifying an Item

`allowedLeadBytes(pool, h)` follows protocol spec §3.2.1 and ZIP 2005:

| Pool | Height `h` | Allowed lead bytes |
|---|---|---|
| Sapling | below Canopy | `{0x01}` |
| Sapling | Canopy to Canopy + ZIP212GracePeriod − 1 | `{0x01, 0x02}` |
| Sapling | from Canopy + ZIP212GracePeriod | `{0x02}` |
| Orchard | any | `{0x02}` |
| Ironwood | any | `{0x03}` |

On mainnet, Canopy is at height 1,046,400 and the grace period ends at 1,078,656. `h` is the height of the block that contains the transaction. A Verifier that accepts a mempool transaction uses the height of the next block.

Common steps:

1. Decode the string and enforce the canonical form. Check the HRP against the expected network and check `version`.
2. Obtain the transaction bytes and `h` from chain data. Compute the txid from those bytes by the rule for their version, and check that it equals `txid`.
3. Resolve `index` only within the bundle that the typecode selects. Reject when that bundle is absent or `index` is out of range. Read `cmu` or `cmx`, the on-chain `ephemeralKey` bytes, `C_enc`, and, for Orchard and Ironwood, `rho` (the nullifier field of the action).
4. Decode `pk_d`. Sapling: `abst_J(pk_d)` MUST be a non-identity point of the prime-order subgroup, and its encoding MUST equal the body bytes. Orchard and Ironwood: `abst_P(pk_d)` MUST be a non-identity point, and its encoding MUST equal the body bytes.

Types `0x02` (Sapling), `0x03` (Orchard) and `0x06` (Ironwood):

1. Derive `esk` from `rseed`, plus `psi` for Orchard and Ironwood. Orchard and Ironwood derivations take `rho` as input and use the same functions for both lead bytes (ZIP 212, protocol spec §4.7.2 and §4.7.3, ZIP 2005).
2. Compute `sharedSecret = KA.Agree(esk, pk_d)` and `K_enc = KDF(sharedSecret, ephemeralKey)`, with `ephemeralKey` as the on-chain bytes.
3. Decrypt `C_enc` with `K_enc` to get `(leadByte, d, v, rseed', memo)`. Reject on AEAD failure.
4. Check `rseed' = rseed`. Check that `leadByte` is `0x02` for types `0x02` and `0x03`, and `0x03` for type `0x06`, and that `leadByte ∈ allowedLeadBytes(pool, h)`.
5. Compute `g_d = DiversifyHash(d)`. Reject when it returns ⊥. Check that `repr([esk] g_d)` equals the on-chain `ephemeralKey` bytes.
6. Derive `rcm`:
   - Sapling and Orchard: from `rseed` (and `rho` for Orchard), as in ZIP 212 and §4.7.3.
   - Ironwood: `rcm = H^rcm_rseed(g_d, pk_d, v, rho, psi)`, as in ZIP 2005.
7. Check the note commitment: `cmu` from `(g_d, pk_d, v, rcm)`, or `cmx = Extract(NoteCommit^Orchard_rcm(g_d, pk_d, v, rho, psi))`. Reject when `NoteCommit` returns ⊥. Ironwood uses `NoteCommit^Orchard` unchanged.

Type `0x04`:

1. Reject when the body `esk` is not a canonical encoding of a scalar below `r_J`.
2. Run steps 2 and 3 with the body `esk`. Step 3 gives `rcm` in place of `rseed'`.
3. Check that `leadByte = 0x01` and `leadByte ∈ allowedLeadBytes(Sapling, h)`. Reject when `rcm ≥ r_J`.
4. Run steps 5 and 7.

Type `0x05`:

1. Decrypt `C_enc` with the body `K_enc`. Reject on AEAD failure.
2. Check that `leadByte = 0x01` and `leadByte ∈ allowedLeadBytes(Sapling, h)`. Reject when `rcm ≥ r_J`.
3. Compute `g_d = DiversifyHash(d)` and reject when it returns ⊥.
4. Run step 7.

A Verifier reports the result per Item, plus the typecodes it skipped.

## Pre-ZIP 212 Sapling receivers

A note with lead byte `0x01` carries `rcm` and a random `esk`. Every such note is in a transaction mined below the end of the ZIP 212 grace period, which makes it a v4 transaction or older. Its receiver has `ivk` and `epk` and cannot recover `esk`. The receiver can disclose only `K_enc` (type `0x05`). The Verifier has no check that ties `K_enc` to `epk`.

- P1 and P2 are valid. The commitment check runs on the decrypted fields, and those fields pin the key.
- P6 fails. The transaction author can encrypt `C_enc` under a key the receiver never derives, then publish that key as a type `0x05` Item. The Item verifies, and the receiver's wallet never saw the note.

Wallets show a type `0x05` result as "note contents verified, receipt unverified". The sender of the same output can produce a type `0x04` Item, which gives P6.

## Orchard after NU6.3

NU6.3 (Ironwood, activated at mainnet height 3,428,143) disables ordinary payments inside the Orchard pool and keeps change and spends (ZIP 318). Orchard notes stay decryptable. Type `0x03` covers notes created before NU6.3 and Orchard change created after it. Migration outputs land at the wallet's internal change address in the Ironwood pool. A Discloser uses the internal `ivk` or `ovk` for them.

A v6 transaction can carry both an Orchard and an Ironwood bundle. The lead byte of a non-coinbase output is outside consensus and does not identify the bundle. Only the typecode selects it.

## Test vectors

Generate them in `zcash-test-vectors`. For each typecode, provide the transaction bytes, the Disclosure string, the decoded fields and the verification result. Include a v4 transaction for each Sapling typecode, a v5 transaction, and a v6 transaction that carries Orchard and Ironwood bundles together.

Negative vectors:

- `rseed` altered
- `index` pointing at another output, and `index` out of range
- a type `0x03` Item with index `i` for a v6 transaction whose Ironwood action `i` carries a lead-`0x02` note and whose Orchard bundle has fewer than `i + 1` actions
- `pk_d` altered, which fails decryption or the `epk` check
- Sapling `pk_d` with a small-order component, identity `pk_d`, and a non-canonical `pk_d` encoding
- `d` for which `DiversifyHash` returns ⊥
- lead byte mismatch for the typecode
- a lead-`0x01` Sapling plaintext in a transaction mined after the grace period, disclosed as `0x04` and as `0x05`
- type `0x04` with `esk ≥ r_J`, and a lead-`0x01` plaintext with `rcm ≥ r_J`
- type `0x06` with `rcm` derived by the Orchard rule instead of ZIP 2005's `H^rcm`
- a type `0x05` Item that verifies while the receiver's `ivk` fails to decrypt the output (shows the P6 gap)
- one Sapling output listed as both `0x04` and `0x05`
- non-minimal CompactSize, `length` mismatch, trailing bytes, unsorted Items, uppercase string, non-zero padding
- a Disclosure with no Items, one with only unknown typecodes, and one with an unknown MUST-understand typecode
- HRP for another network
- transaction bytes from a data source whose computed txid differs from `txid`

## Implementation

A crate, working name `zcash_disclosure`, on top of `sapling-crypto`, `zcash_note_encryption` and an `orchard` release that implements ZIP 2005 and the Ironwood bundle. It exposes `produce` from a UFVK and transaction, `encode`/`decode`, and `verify` from transaction bytes and block height. It parses v4, v5 and v6 transactions.

## Open questions

- An optional block height and hash. With them, a Verifier can check inclusion without a txid lookup.
- A network byte in the payload, in addition to the HRP.
- Version `0x01` depends on ZIP 229, which is still a Draft. A change to its txid digest would need a new version.

## References

Statuses as listed on zips.z.cash on 2026-09-29.

- ZIP 212, Allow Recipient to Derive Ephemeral Secret from Note Plaintext
- ZIP 229, Version 6 Transaction Format (Draft)
- ZIP 244, Transaction Identifier Non-Malleability
- ZIP 311, Zcash Payment Disclosures (Draft)
- ZIP 316, Unified Addresses and Unified Viewing Keys
- ZIP 318, Orchard to Ironwood Migration (Draft)
- ZIP 326, NU6.3 Consequences for Wallets (Draft)
- ZIP 2005, Ironwood Quantum Recoverability (Proposed)
- Zcash Protocol Specification, §3.2.1, §4.1.2, §4.1.5, §4.1.6, §4.1.8, §4.7.2, §4.7.3, §4.20, §5.4.1.6, §5.4.8.2, §5.4.8.4, §7.1.1
