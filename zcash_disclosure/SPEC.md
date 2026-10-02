# Draft: Zcash Payment Disclosure Encoding

Status: Draft. Candidate for the unsigned and signed disclosure encodings left open in ZIP 311. Output disclosure covers the Sapling, Orchard and Ironwood pools. Signer support covers Sapling only.

## Terminology

- Disclosure: a string that lets any holder decrypt and check a set of shielded outputs of one transaction.
- Class: unsigned or signed. The HRP states the class.
- Output Item: the per-output part of a Disclosure.
- Signer Item: a proof and a signature by a party that holds a spending key. Only the signed class has Signer Items.
- Message Item: text or a challenge that the signatures bind. Only the signed class has a Message Item.
- Discloser: the party that produces an Output Item. It is the sender (with `ovk`) or the receiver (with `ivk`) of the output.
- Signer: the party that produces a Signer Item.
- Verifier: the party that checks a Disclosure against the transaction bytes.
- Disclosure set: a file of Disclosures for several transactions.
- Address space: the set of addresses one key tree derives for a pool family. Sapling is one address space. Orchard and Ironwood share another.

## Classes

A proof of payment has three parts. The class tells the Verifier which parts the Disclosure carries.

| Part | Shows | Unsigned | Signed |
|---|---|---|---|
| Output Items | what was paid, and to which address | yes | yes |
| Signer Items | who made the Disclosure: a payer or an address owner | no | yes |
| Message Item | the context of the Disclosure, and freshness with a challenge | no | yes |

- Unsigned: Output Items only. A viewing key is sufficient to produce it. It is a bearer string.
- Signed: Output Items, one or more Signer Items and an optional Message Item. A spending key is necessary to produce it. The signatures cover the full body.

The class is a rule of the format and not a claim by the producer. A signed-class string without a valid Signer Item is invalid.

Support in version `0x01`:

| Part | Sapling | Orchard | Ironwood | Transparent |
|---|---|---|---|---|
| Output Items | yes | yes | yes | not applicable |
| Spend signer | yes | reserved | reserved | reserved |
| Address proof | yes | reserved | reserved | not applicable |

A signed Disclosure needs a Sapling spend in the transaction, or a Sapling output whose receiver signs. It can carry Orchard and Ironwood Output Items.

## Properties

A Verifier that accepts an Output Item obtains P1 to P6, in the two classes. Each property cites the protocol-spec security requirements it depends on. Section numbers refer to the Zcash Protocol Specification.

- P1, note binding. The output at the stated index commits to `(g_d, pk_d, v, rcm)`, plus `(rho, psi)` for Orchard and Ironwood. Depends on computational binding (§4.1.8) of `NoteCommit^Sapling` (§5.4.8.2) and `NoteCommit^Orchard` (§5.4.8.4).
- P2, memo binding. One output yields one memo under verification. The note fields occupy the plaintext bytes before the memo. A second key that also decrypts `C_enc` changes those fields, and the commitment check then fails. Depends on the same requirements as P1.
- P3, scope. A holder learns `d`, `pk_d`, `v` and the memo of each listed output. Depends on IND-CCA2 security and key privacy of the in-band encryption scheme (§4.1.6) for the unlisted outputs, the PRF requirement on `PRF^expand` (§4.1.2), and the key agreement requirement (§4.1.5), which makes `ivk` infeasible to recover from `(g_d, pk_d)`. Two consequences follow from public transaction data:
  - Each disclosed `v`, with the bundle's public `valueBalance`, gives the net value of the unlisted spends and outputs of that bundle. When the bundle has no shielded spends and one other output, the holder learns that output's value.
  - A transaction author can reuse `rseed` or `esk` across outputs to one address. A holder of one such Item can then find and open the other outputs.
- P4, linkability. Items with equal `(address space, d, pk_d)` belong to one receiver address. Holders of several Disclosures can link them on that triple. Linkers MUST include the address space in the key: a Sapling and an Orchard `(d, pk_d)` can share bytes. All change and ZIP 318 migration outputs of an account go to one internal address per address space. Their Items link to each other. That no further link exists depends on Unlinkability of `DiversifyHash` (§5.4.1.6).
- P5, bearer. Any holder can verify and forward a Disclosure of either class. A Disclosure is irrevocable once shared. In the unsigned class, Items compose freely: anyone can remove Items or merge Items for the same txid, and a Disclosure carries no evidence that one party produced all its Items. Depends on no cryptographic requirement.
- P6, receivability. For types `0x02`, `0x03`, `0x04` and `0x06`, the owner of the `ivk` with `pk_d = [ivk] g_d` derives the same `K_enc` from `epk` and accepts the plaintext under the protocol's lead-byte rules. Type `0x05` lacks P6. Follows from verification steps 4 and 5 and from the correctness of `KA.Agree` (§4.1.5).

A Verifier that accepts a signed Disclosure also obtains P7 to P10.

- P7, body binding. The signatures cover the HRP, `txid` and every Item. A holder cannot add, remove, change or merge Items and keep the signatures valid. A holder can remove the Signer Items and the Message Item and encode the Output Items again as an unsigned Disclosure. Depends on SURK-CMA security of `SpendAuthSig` (§4.1.7.1, §4.15).
- P8, spend authority. For each spend signer Item, a party that holds the spend authorizing key of the note that Sapling spend `index` consumed signed this body. Depends on P7's requirement and on knowledge soundness of the proving system (§4.1.13) for the Spend statement (§4.18.2).
- P9, address control. For each type `0xE1` and `0xE2` Item, the Signer holds the spending key of `(d, pk_d)`. For type `0xE2`, that address is the receiver of a listed Sapling output. Depends on the same requirements as P8.
- P10, freshness. Applies only when the Message Item holds a challenge that this Verifier issued. The Signer then made the signature after the challenge. Without such a challenge, a holder can present a copied signed Disclosure as its own.

Signer Items add these links:

- A spend signer Item links its Signer to the nullifier of Sapling spend `index`.
- Type `0xE1` and `0xE2` Items for one address have the same `nf_addr` (ZIP 304).

The Disclosure carries no evidence for the facts below. The Verifier obtains the first two from chain data. The others stay unknown to the Verifier.

- Inclusion and depth. The block height also feeds the lead-byte check.
- Transaction validity: the zk-SNARKs and signatures.
- Spend status. Nullifier derivation needs `nk`, which stays with the wallet.
- Authorship, in the unsigned class. For types `0x02`, `0x03`, `0x05` and `0x06`, the sender and the receiver can each produce the same Item. Only the transaction author or a holder of the sender's `ovk` knows `esk` for a lead-byte-`0x01` note. A type `0x04` Item reveals that its Discloser is on the sender side.
- The owner of a receiver address, unless a type `0xE2` Item covers it. The Verifier learns from another source which party an address belongs to.
- The other spenders, in the signed class. A Signer Item covers one input. A transaction can have inputs without a Signer Item.
- The person behind a key. A Signer Item shows control of a key, and any party with access to that key is a Signer.

### Adversaries that compute discrete logarithms

This section is informative. It considers an adversary, an efficient algorithm as in the protocol spec's security definitions, that can also compute discrete logarithms on Jubjub and Pallas, for example with a quantum computer. The requirements that P1 to P4 and P7 to P9 cite then fail. Type `0x06` keeps a hash-based bound on P1, given at the end of this section. This adversary obtains `ivk` from `pk_d = [ivk] g_d` and reads every note of that scope. It obtains `ask` from `rk` and forges Signer Items. An Item for a change or migration output exposes the internal scope. Transaction validity fails as well. A Disclosure stored today stays exposed to this adversary later. For type `0x06`, the `H^rcm` check of ZIP 2005 reduces a forged opening to a collision search, estimated at 2^127 evaluations classically and 2^85 with a quantum collision algorithm.

## Encoding

```
Disclosure = Bech32m(HRP, payload)
payload    = version || txid || Item*
Item       = typecode || length || body
```

| Class | Mainnet | Testnet | Regtest |
|---|---|---|---|
| Unsigned | `zdu` | `zdutest` | `zduregtest` |
| Signed | `zds` | `zdstest` | `zdsregtest` |

- The HRP is the only class and network binding in the string. The signature digest of the signed class includes it. Implementations use a Bech32m decoder without the 90-character limit, as ZIP 316 does. Register the six HRPs in SLIP-0173.
- `version` is one byte, `0x01`.
- `txid` is 32 bytes in internal byte order:
  - v4: SHA-256d of the raw transaction encoding (protocol spec §7.1.1).
  - v5: ZIP 244.
  - v6: ZIP 229, which adds `ironwood_digest_v6` to the ZIP 244 digest.
- `typecode` and `length` are CompactSize. `length` is the byte length of `body`.
- `index` is CompactSize. It is the position in the bundle that the typecode selects.

Output Items, for the two classes:

| Typecode | Bundle | Note plaintext lead byte | Body |
|---|---|---|---|
| `0x02` | Sapling outputs | `0x02` (ZIP 212) | `index \|\| pk_d \|\| rseed` |
| `0x03` | `vActionsOrchard` | `0x02` | `index \|\| pk_d \|\| rseed` |
| `0x04` | Sapling outputs | `0x01` (pre-ZIP 212), sender | `index \|\| pk_d \|\| esk` |
| `0x05` | Sapling outputs | `0x01` (pre-ZIP 212), receiver | `index \|\| pk_d \|\| K_enc` |
| `0x06` | `vActionsIronwood` | `0x03` (ZIP 2005) | `index \|\| pk_d \|\| rseed` |

Each Output Item body is 1 to 5 bytes of `index` plus 64 bytes. `d`, `v` and the memo come from decryption.

Message and Signer Items, for the signed class only:

| Typecode | Item | Body |
|---|---|---|
| `0x10` | Message | `msg` |
| `0xE0` | Sapling spend signer | `index \|\| cv \|\| rk \|\| zkproof_spend \|\| sig` |
| `0xE1` | Sapling spend signer with address | `index \|\| cv \|\| rk \|\| zkproof_spend \|\| d \|\| pk_d \|\| nf_addr \|\| zkproof_addr \|\| sig` |
| `0xE2` | Sapling address owner signer | `d \|\| pk_d \|\| nf_addr \|\| rk \|\| zkproof_addr \|\| sig` |
| `0xE3` to `0xEF` | Reserved: Signer Items for Orchard, Ironwood and transparent inputs | |

- For types `0xE0` and `0xE1`, `index` is the position in the Sapling spends of the transaction.
- `cv`, `rk`, `pk_d` and `nf_addr` are 32 bytes. `d` is 11 bytes. `zkproof_spend` and `zkproof_addr` are 192 bytes. `sig` is 64 bytes and is the last field of each Signer Item.
- `msg` is 1 to 512 bytes. The format gives it no structure. A Disclosure without a Message Item has the empty message.

Typecodes `0xE0` to `0xFF` are MUST-understand. A Verifier skips any other unknown typecode and reports it. A version `0x01` Verifier thus rejects a Disclosure that has a reserved Signer Item, and does not report it as signed.

The unsigned class has no free-text field. Nothing authenticates text outside the memo. Any holder could edit it, and a Verifier would show it next to verified data. Context such as an invoice number goes in the memo when the payment is made, in the channel that carries the Disclosure, or in the Message Item of a signed Disclosure.

### Canonical form

A decoder rejects the string when any rule below fails. Each payload then has exactly one string.

- The string is all lowercase, and the Bech32m padding is at most 4 bits, all zero.
- Every CompactSize is minimal.
- For known typecodes, `length` equals the body size. For type `0x10`, `length` is 1 to 512. No bytes follow the last Item.
- Items are strictly increasing by `(typecode, key)`. The key is `index` for Items that have one, `d || pk_d` in byte order for type `0xE2`, and empty for type `0x10`.
- An output appears at most once. Uniqueness is keyed on `(bundle, index)`. Types `0x02`, `0x04` and `0x05` share the Sapling bundle.
- A Sapling spend appears at most once. Types `0xE0` and `0xE1` share the Sapling spends.
- The Disclosure has no Item with an unknown MUST-understand typecode.
- An unsigned Disclosure has at least one Output Item with a known typecode. It has no Message Item and no Signer Item.
- A signed Disclosure has at least one Signer Item. It can have zero Output Items.
- The Disclosure has at most 64 Items, and each body is at most 1024 bytes.

### Signature digest

All Signer Items of a Disclosure sign the same digest.

```
signingBody = payload, with the sig field of each Signer Item omitted
digest      = BLAKE2b-256("ZIP311Signed" || coinType, CompactSize(len(HRP)) || HRP || signingBody)
```

- The `length` field of each Signer Item is unchanged in `signingBody`.
- `coinType` is the 4-byte little-endian SLIP-44 coin type in its index form: 133 for mainnet, 1 for testnet and regtest.
- `BLAKE2b-256(p, x)` is unkeyed BLAKE2b-256 with the 16-byte personalization `p` and the input `x`, as in ZIP 304.

The digest covers each `zkproof`. This prevents a holder from re-randomizing a proof to get a second valid encoding.

## Disclosure sets

A Disclosure covers one transaction. A Disclosure set covers several. It is a UTF-8 text file with the extension `.zdisc`.

- Each line is one Disclosure in canonical form, and every line ends with LF.
- All lines use HRPs of the same network. A set can have lines of the two classes.
- A txid appears on at most one line. Items for one transaction go into one Disclosure.
- The order of lines carries no meaning.

A Verifier checks each line on its own and reports the result and the class per line. A set tells the Verifier that one party disclosed these transactions together. The Verifier learns the same from separate Disclosures sent together. No signature covers the set.

## Producing an Output Item

Types `0x02`, `0x03` and `0x06` need `rseed`.

- Receiver: trial-decrypt `C_enc` with `ivk` (the internal `ivk` for change) and read `rseed` from the plaintext.
- Sender: derive `ock` from `ovk`, decrypt `C_out` to get `(pk_d, esk)`, derive `K_enc` and decrypt `C_enc` to read `rseed`. This path requires that the transaction was built with an `ovk`. A transaction built with `ovk = ⊥` leaves only the receiver path.

Type `0x04` uses the sender path and takes `esk` from `C_out`. Type `0x05` uses the receiver path and takes `K_enc`. A sender produces `0x04` for a lead-byte-`0x01` note, since `0x04` gives P6.

Ironwood uses the Orchard key tree, addresses and viewing keys (ZIP 2005). A wallet produces type `0x03` and type `0x06` Items with the same Orchard `ivk` and `ovk`. The `use_qsk` flag changes how `rivk` is derived, and with it `ivk`. It has no effect on the Item or on verification.

A Discloser MUST check, before it emits an Item, that the Item's secret (`rseed`, `esk` or `K_enc`) is unique among the outputs it knows at that address. It warns the user when the secret repeats.

A Discloser SHOULD ask for explicit confirmation before it discloses an internal-scope output (change or migration). The confirmation states that the Item links to every other change Item of the account (P4) and exposes the internal scope to a discrete-log adversary.

## Producing a signed Disclosure

A viewing key cannot produce a Signer Item. Each Signer needs an expanded spending key `(ask, nsk)` and the Sapling spend parameters.

1. Fix the Output Items and the Message Item.
2. Each Signer makes the fields of its Signer Item before `sig`, with a new random `α` for each Disclosure:
   - Types `0xE0` and `0xE1`: make a Sapling spend proof for the note that Sapling spend `index` consumed, with the anchor of that spend and a new `rcv`. This needs the note and its Merkle path to that anchor. It gives `(cv, rk, zkproof_spend)`.
   - Type `0xE1`: also make the proof of the ZIP 304 signature algorithm for the Signer's payment address `(d, pk_d)`, with the same `α` and `rk`. It gives `(nf_addr, zkproof_addr)`.
   - Type `0xE2`: make the proof of the ZIP 304 signature algorithm for the receiver address `(d, pk_d)`. It gives `(nf_addr, rk, zkproof_addr)`.
3. Put all Items in canonical order and compute `digest`. All Signer Items are in place before any Signer signs.
4. Each Signer computes `rsk = SpendAuthSig.RandomizePrivate(α, ask)` and `sig = SpendAuthSig.Sign(rsk, digest)`.

A Signer of type `0xE2` uses the digest of this specification and does not use the ZIP 304 digest. A ZIP 304 signature that a user made for another purpose is thus not valid as a Signer Item.

A Signer puts a challenge from the Verifier in the Message Item when the Verifier gives one.

## Verifying a Disclosure

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

1. Decode the string and enforce the canonical form. Check the HRP against the expected network, take the class from the HRP, and check `version`.
2. Obtain the transaction bytes and `h` from chain data. Compute the txid from those bytes by the rule for their version, and check that it equals `txid`.
3. Verify each Output Item.
4. Signed class: compute `digest` and verify each Signer Item.

In the unsigned class, a Verifier reports the result per Item. In the signed class, a Verifier rejects the Disclosure when any Item fails, because the signatures cover the body as a whole.

### Output Items

Steps for all types:

1. Resolve `index` only within the bundle that the typecode selects. Reject when that bundle is absent or `index` is out of range. Read `cmu` or `cmx`, the on-chain `ephemeralKey` bytes, `C_enc`, and, for Orchard and Ironwood, `rho` (the nullifier field of the action).
2. Decode `pk_d`. Sapling: `abst_J(pk_d)` MUST be a non-identity point of the prime-order subgroup, and its encoding MUST equal the body bytes. Orchard and Ironwood: `abst_P(pk_d)` MUST be a non-identity point, and its encoding MUST equal the body bytes.

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

### Signer Items

Types `0xE0` and `0xE1`:

1. Reject when the transaction has no Sapling spends or `index` is out of range. Read the anchor `rt` and the nullifier `nf` of that spend. For v5 and later transactions, `rt` is the anchor of the Sapling bundle.
2. Decode `cv` and `rk`. Each MUST be a canonical encoding of a Jubjub point that is not of small order, as for a Spend description (§4.4).
3. Check `SpendAuthSig.Verify(rk, digest, sig) = 1` (§4.15, §5.4.7.1).
4. Verify `zkproof_spend` as a Sapling spend proof with primary input `(rt, cv, nf, rk)` (§4.18.2).
5. Type `0xE1`: verify the address proof with the `rk` of this Item.

Type `0xE2`:

1. Decode `rk` as in step 2 above.
2. Check `SpendAuthSig.Verify(rk, digest, sig) = 1`.
3. Verify the address proof.
4. Check that `(d, pk_d)` equals the receiver address of an Output Item of type `0x02`, `0x04` or `0x05` in this Disclosure.

Address proof, for types `0xE1` and `0xE2`. It is the ZIP 304 verification algorithm without its signature check:

1. Decode `pk_d` as for a Sapling Output Item. Compute `g_d = DiversifyHash(d)` and reject when it returns ⊥.
2. Compute `cm = NoteCommit^Sapling_0(repr_J(g_d), repr_J(pk_d), 1)`, the root `rt_addr` of the Sapling tree that has `cm` at position 0 and `Uncommitted^Sapling` at all other positions, and `cv_addr = ValueCommit_0(1)` (§5.4.8.3).
3. Verify `zkproof_addr` as a Sapling spend proof with primary input `(rt_addr, cv_addr, nf_addr, rk)`.

## Verifier report

A Verifier MUST show the statements below for each Disclosure. It MUST NOT show a statement that the checks do not support.

For the two classes:

- The class: unsigned or signed.
- For each Output Item: "Output `index` of transaction `txid` pays `v` to address `(d, pk_d)`, with memo `memo`: verified". For type `0x05`, add "receipt unverified".
- The block height of the transaction, or that the transaction is not mined.
- The typecodes it skipped.

Unsigned class:

- "Payer: not proven."
- "Producer of this Disclosure: not proven."
- "Owner of each receiver address: not proven."

Signed class:

- For each type `0xE0` Item: "A holder of the spending key for Sapling input `index` signed this Disclosure."
- For each type `0xE1` Item: the same, plus "The same party controls address `(d, pk_d)`."
- For each type `0xE2` Item: "The owner of address `(d, pk_d)`, the receiver of output `index`, signed this Disclosure."
- When the Disclosure has no spend signer Item: "Payer: not proven."
- The number of transaction inputs, of all pools, that have no Signer Item.
- The message. A Verifier shows it as text when it is valid UTF-8, and as hexadecimal otherwise.
- "Freshness: proven" only when the message contains a challenge that this Verifier issued. Otherwise "Freshness: not proven".

## Pre-ZIP 212 Sapling receivers

A note with lead byte `0x01` carries `rcm` and a random `esk`. Every such note is in a transaction mined below the end of the ZIP 212 grace period, which makes it a v4 transaction or older. Its receiver has `ivk` and `epk` and cannot recover `esk`. The receiver can disclose only `K_enc` (type `0x05`). The Verifier has no check that ties `K_enc` to `epk`.

- P1 and P2 are valid. The commitment check runs on the decrypted fields, and those fields pin the key.
- P6 fails. The transaction author can encrypt `C_enc` under a key the receiver never derives, then publish that key as a type `0x05` Item. The Item verifies, and the receiver's wallet never saw the note.

The sender of the same output can produce a type `0x04` Item, which gives P6. A type `0xE2` Item for the receiver address shows that the address owner knows the output. It does not give P6.

## Orchard after NU6.3

NU6.3 (Ironwood, activated at mainnet height 3,428,143) disables ordinary payments inside the Orchard pool and keeps change and spends (ZIP 318). Orchard notes stay decryptable. Type `0x03` covers notes created before NU6.3 and Orchard change created after it. Migration outputs land at the wallet's internal change address in the Ironwood pool. A Discloser uses the internal `ivk` or `ovk` for them.

A v6 transaction can carry both an Orchard and an Ironwood bundle. The lead byte of a non-coinbase output is outside consensus and does not identify the bundle. Only the typecode selects it.

## Relation to ZIP 311 and ZIP 304

This section is informative.

Taken from ZIP 311:

- The spend signer: a new Sapling spend proof against the anchor and nullifier of the transaction, and a `spendAuthSig` over the encoded body.
- The optional payment address proof of the sender (type `0xE1`), which reuses `α` and `rk` of the spend proof.
- The message that the signatures bind.
- The digest construction and its personalization.

Differences from ZIP 311:

- Output disclosure. ZIP 311 discloses a Sapling output with `ock`, which only the sender has. This specification discloses the secret of the output (`rseed`, `esk` or `K_enc`), which the sender or the receiver has, and covers Orchard and Ironwood.
- Unsigned class. ZIP 311 rejects a disclosure without a proof of spend authority, so that a holder cannot remove invalid signatures and get a disclosure that a UI shows as valid. This specification permits a Disclosure without Signer Items, with a different HRP and the Verifier report as the protection.
- Receiver signer. ZIP 311 requires that only a sender can create a disclosure. Type `0xE2` lets the owner of a receiver address sign. A signed Disclosure thus needs one or more Signer Items of any type, and the Verifier report states which type.
- Digest input. The digest includes the HRP before the encoded body.

Open in ZIP 311 and reserved here: Signer Items for Orchard and for transparent inputs (BIP 322).

ZIP 304 defines the address proof. This specification uses its proof with the digest above in place of the ZIP 304 digest. ZIP 304 covers Sapling addresses only.

## Test vectors

Generate them in `zcash-test-vectors`. For each typecode, provide the transaction bytes, the Disclosure string, the decoded fields and the verification result. Include a v4 transaction for each Sapling typecode, a v5 transaction, and a v6 transaction that carries Orchard and Ironwood bundles together. For the signed class, include each Signer typecode, a Disclosure with a Message Item, a Disclosure with zero Output Items, and a Disclosure with two Signers.

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
- an unsigned Disclosure with no Items, one with only unknown typecodes, and one with an unknown MUST-understand typecode
- HRP for another network
- transaction bytes from a data source whose computed txid differs from `txid`
- an unsigned-class string with a Message Item, and one with a Signer Item
- a signed-class string with no Signer Item
- a signed Disclosure with the message altered, with an Output Item removed, and with an Output Item added
- a signed Disclosure encoded again with the HRP of another network
- a Signer Item with `zkproof_spend` re-randomized
- a spend signer Item with `index` pointing at another spend, and `index` out of range
- one Sapling spend listed as both `0xE0` and `0xE1`
- `rk` of small order, and `cv` of small order
- a type `0xE1` Item whose address proof uses an `rk` other than the `rk` of the Item
- a type `0xE2` Item for an address that is not the receiver of a listed Sapling output
- a type `0xE2` Item whose `sig` is a ZIP 304 signature over the same proof
- a Message Item with an empty body, and one above the size limit
- a reserved Signer typecode

## Implementation

A crate, working name `zcash_disclosure`, on top of `sapling-crypto`, `zcash_note_encryption` and an `orchard` release that implements ZIP 2005 and the Ironwood bundle. It exposes `discover` for Output Items from viewing keys and a transaction, `encode`/`decode`, and `verify` from a transaction and block height. It accepts v4, v5 and v6 transactions. Signer Items need a proof generation key, a spend authorizing key, the witness of the spent note and the Sapling spend parameters to produce, and the Sapling spend verifying key to verify. The entry points for the reserved Signer Items (Orchard, Ironwood, transparent) are placeholders that panic. A decoder rejects the reserved typecodes.

## Open questions

- An optional block height and hash. With them, a Verifier can check inclusion without a txid lookup.
- A network byte in the payload, in addition to the HRP.
- Version `0x01` depends on ZIP 229, which is still a Draft. A change to its txid digest would need a new version.
- The personalization `ZIP311Signed` assumes that ZIP 311 adopts this encoding. Without that, the digest needs its own personalization.
- The receiver signer (type `0xE2`) conflicts with the ZIP 311 requirement that only a sender creates a disclosure.
- A spend signer for Orchard and Ironwood. The Action circuit takes `ak`, `nk` and `rivk` and no `ask`, so a full viewing key can make the proof and only the signature needs `ask`. No ZIP specifies this construction. It needs an analysis of the output half of the Action and of the Merkle path check for a zero-value note.
- An address proof for Orchard and Ironwood. ZIP 304 has no equivalent for these pools.
- A signer for transparent inputs. ZIP 311 leaves BIP 322 support open.

## References

Statuses as listed on zips.z.cash on 2026-10-01.

- ZIP 212, Allow Recipient to Derive Ephemeral Secret from Note Plaintext
- ZIP 229, Version 6 Transaction Format (Draft)
- ZIP 244, Transaction Identifier Non-Malleability
- ZIP 304, Sapling Address Signatures (Draft)
- ZIP 311, Zcash Payment Disclosures (Draft)
- ZIP 316, Unified Addresses and Unified Viewing Keys
- ZIP 318, Orchard to Ironwood Migration (Draft)
- ZIP 326, NU6.3 Consequences for Wallets (Draft)
- ZIP 2005, Ironwood Quantum Recoverability (Proposed)
- SLIP-0044, Registered coin types for BIP-0044
- SLIP-0173, Registered human-readable parts for BIP-0173
- Zcash Protocol Specification, §3.2.1, §4.1.2, §4.1.5, §4.1.6, §4.1.7.1, §4.1.8, §4.1.13, §4.4, §4.7.2, §4.7.3, §4.15, §4.18.2, §4.20, §5.4.1.6, §5.4.7.1, §5.4.8.2, §5.4.8.3, §5.4.8.4, §7.1.1
