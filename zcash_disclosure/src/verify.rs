//! Verification of a [`Disclosure`] against the transaction it covers.

use std::fmt;

use bls12_381::Bls12;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use ff::{FromUniformBytes, PrimeField};
use group::Group;
use orchard::{
    Action,
    note_encryption::{IronwoodDomain, OrchardDomain},
};
use pasta_curves::pallas;
use redjubjub::{Signature, SpendAuth, VerificationKey};
use sapling::{
    PaymentAddress, Rseed, SaplingVerificationContext,
    bundle::{Authorization, GrothProofBytes, OutputDescription, SpendDescription},
    circuit::PreparedSpendVerifyingKey,
    note_encryption::{SaplingDomain, Zip212Enforcement},
    value::ValueCommitment,
};
use zcash_note_encryption::{
    Domain, OUT_PLAINTEXT_SIZE, OutPlaintextBytes, ShieldedOutput, try_output_recovery_with_pkd_esk,
};
use zcash_primitives::transaction::{Transaction, components::sapling::zip212_enforcement};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, NetworkType, Parameters},
};
use zcash_spec::PrfExpand;

use crate::{
    encoding::{
        AddressProof, Class, Disclosure, Item, Kind, Message, Pool, Signer, SignerBody, SignerKind,
    },
    zip304::AddressStatement,
};

/// The number of shielded inputs of one Sprout JoinSplit description.
const SPROUT_INPUTS_PER_JOINSPLIT: usize = 2;

/// A note that a verified Item opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisclosedNote {
    /// The Item's type.
    pub kind: Kind,
    /// The position of the output in its bundle.
    pub index: u32,
    /// The receiver's diversifier.
    pub diversifier: [u8; 11],
    /// The receiver's transmission key.
    pub pk_d: [u8; 32],
    /// The note value in zatoshis.
    pub value: u64,
    /// The memo field.
    pub memo: [u8; 512],
}

impl DisclosedNote {
    /// Whether the owner of the receiver's incoming viewing key decrypts and accepts this
    /// output (property P6). A [`Kind::SaplingLegacyReceiver`] Item cannot show it.
    pub fn receivable(&self) -> bool {
        self.kind != Kind::SaplingLegacyReceiver
    }
}

/// Why an Item failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemError {
    /// The transaction has no bundle for the Item's pool.
    MissingBundle,
    /// The index is past the end of the bundle.
    IndexOutOfRange,
    /// The Item was checked against a bundle of another pool.
    WrongPool,
    /// `pk_d` is not a canonical, valid, non-identity point.
    InvalidPkd,
    /// The secret does not encode a valid key.
    InvalidSecret,
    /// `[esk] g_d` does not match the output's ephemeral key.
    EphemeralKeyMismatch,
    /// Decryption failed, or the plaintext's lead byte, `rseed` or note commitment does not
    /// match.
    Rejected,
}

impl fmt::Display for ItemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ItemError::MissingBundle => "the transaction has no bundle for this pool",
            ItemError::IndexOutOfRange => "the index is past the end of the bundle",
            ItemError::WrongPool => "the item belongs to another pool",
            ItemError::InvalidPkd => "pk_d is not a valid transmission key",
            ItemError::InvalidSecret => "the secret does not encode a valid key",
            ItemError::EphemeralKeyMismatch => "[esk] g_d does not match the ephemeral key",
            ItemError::Rejected => "the output does not open to a valid note under this item",
        })
    }
}

impl std::error::Error for ItemError {}

/// Why a Signer Item failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    /// The transaction has no Sapling spends.
    MissingBundle,
    /// The index is past the end of the Sapling spends.
    IndexOutOfRange,
    /// The Signer Item was checked as an Item of another type.
    WrongKind,
    /// `cv` is not a canonical point, or it is of small order.
    InvalidCv,
    /// `rk` is not a canonical point, or it is of small order.
    InvalidRk,
    /// A proof is not a valid encoding.
    InvalidProofEncoding,
    /// `(d, pk_d)` is not a valid Sapling payment address.
    InvalidAddress,
    /// The signature is not valid under `rk` over the digest of the Disclosure.
    InvalidSignature,
    /// A proof is not valid for its statement.
    InvalidProof,
    /// The address of an address owner Signer Item is not the receiver of a Sapling
    /// Output Item of the Disclosure.
    AddressNotDisclosed,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignerError::MissingBundle => "the transaction has no Sapling spends",
            SignerError::IndexOutOfRange => "the index is past the end of the Sapling spends",
            SignerError::WrongKind => "the signer item has another type",
            SignerError::InvalidCv => "cv is not a valid value commitment",
            SignerError::InvalidRk => "rk is not a valid randomized key",
            SignerError::InvalidProofEncoding => "a proof is not a valid encoding",
            SignerError::InvalidAddress => "(d, pk_d) is not a valid payment address",
            SignerError::InvalidSignature => "the signature is not valid",
            SignerError::InvalidProof => "a proof is not valid for its statement",
            SignerError::AddressNotDisclosed => {
                "the address is not the receiver of a disclosed Sapling output"
            }
        })
    }
}

impl std::error::Error for SignerError {}

/// A verified spend signer Item: a holder of the spending key for a Sapling input signed
/// the Disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendAuthority {
    index: u32,
    address: Option<PaymentAddress>,
}

impl SpendAuthority {
    /// The position of the input in the Sapling spends of the transaction.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// A payment address that the same party controls, when the Item proves one.
    pub fn address(&self) -> Option<&PaymentAddress> {
        self.address.as_ref()
    }
}

/// A verified address owner signer Item: the owner of the receiver address of listed
/// Sapling outputs signed the Disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressOwner {
    address: PaymentAddress,
    outputs: Vec<u32>,
}

impl AddressOwner {
    /// The address that the Signer controls.
    pub fn address(&self) -> &PaymentAddress {
        &self.address
    }

    /// The positions, in the Sapling outputs, of the listed outputs to this address.
    pub fn outputs(&self) -> &[u32] {
        &self.outputs
    }
}

/// What a verified Signer Item shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerStatement {
    /// A payer signed the Disclosure.
    SpendAuthority(SpendAuthority),
    /// The owner of a receiver address signed the Disclosure.
    AddressOwner(AddressOwner),
}

/// The part of a [`Report`] that only a signed Disclosure has.
#[derive(Clone, Debug)]
pub struct SignedReport {
    signers: Vec<SignerStatement>,
    message: Option<Message>,
    inputs_without_signer: usize,
}

impl SignedReport {
    /// One statement per Signer Item, in canonical order.
    pub fn signers(&self) -> &[SignerStatement] {
        &self.signers
    }

    /// The message that the signatures bind. It shows freshness only when it holds a
    /// challenge that this Verifier issued.
    pub fn message(&self) -> Option<&Message> {
        self.message.as_ref()
    }

    /// The number of transaction inputs, of all pools, that have no Signer Item.
    pub fn inputs_without_signer(&self) -> usize {
        self.inputs_without_signer
    }

    /// Whether a party with spend authority over an input signed the Disclosure.
    pub fn payer_proven(&self) -> bool {
        self.signers
            .iter()
            .any(|signer| matches!(signer, SignerStatement::SpendAuthority(_)))
    }
}

/// Why a Disclosure could not be checked against a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The Disclosure's HRP binds it to another network.
    NetworkMismatch {
        /// The network of the consensus parameters.
        expected: NetworkType,
        /// The network of the Disclosure.
        found: NetworkType,
    },
    /// The transaction's txid differs from the Disclosure's.
    TxidMismatch,
    /// The Disclosure is signed, and the caller gave no Sapling spend verifying key.
    MissingSpendVerifyingKey,
    /// An Output Item of a signed Disclosure failed. The signatures cover the body as a
    /// whole, so the Disclosure is rejected.
    Item {
        /// The Item's type.
        kind: Kind,
        /// The position of the output in its bundle.
        index: u32,
        /// The reason.
        error: ItemError,
    },
    /// A Signer Item failed.
    Signer {
        /// The Item's type.
        kind: SignerKind,
        /// The reason.
        error: SignerError,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::NetworkMismatch { expected, found } => {
                write!(f, "disclosure is for {found:?}, expected {expected:?}")
            }
            VerifyError::TxidMismatch => write!(f, "the transaction does not match the txid"),
            VerifyError::MissingSpendVerifyingKey => write!(
                f,
                "a signed disclosure needs the Sapling spend verifying key"
            ),
            VerifyError::Item { kind, index, error } => write!(
                f,
                "output item {index} of typecode {:#04x}: {error}",
                kind.typecode()
            ),
            VerifyError::Signer { kind, error } => {
                write!(
                    f,
                    "signer item of typecode {:#04x}: {error}",
                    kind.typecode()
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// The result of checking a Disclosure, one entry per known Output Item.
#[derive(Clone, Debug)]
pub struct Report {
    /// The transaction.
    pub txid: TxId,
    /// The class of the Disclosure.
    pub class: Class,
    /// Each known Output Item with its result. Every result of a signed Disclosure is
    /// `Ok`.
    pub items: Vec<(Item, Result<DisclosedNote, ItemError>)>,
    /// The typecodes of the Items the Verifier skipped.
    pub skipped: Vec<u64>,
    /// What the Signer Items show. `None` for an unsigned Disclosure, which proves no
    /// payer, no producer and no address owner.
    pub signed: Option<SignedReport>,
}

/// Checks `disclosure` against `tx`.
///
/// `height` is the height of the block that contains `tx`, or the height of the next block
/// for a mempool transaction. It sets which note plaintext lead bytes are valid. The caller
/// establishes that `tx` is in a block, how deep, and that its proofs and signatures are
/// valid.
///
/// `spend_vk` is the verifying key of the Sapling Spend circuit. Only a signed Disclosure
/// needs it.
///
/// An unsigned Disclosure gets one result per Output Item. A signed Disclosure is
/// rejected as a whole when any Item fails.
///
/// # Errors
///
/// - [`VerifyError::NetworkMismatch`] or [`VerifyError::TxidMismatch`] when the
///   Disclosure is for another network or transaction.
/// - [`VerifyError::MissingSpendVerifyingKey`] when the Disclosure is signed and
///   `spend_vk` is `None`.
/// - [`VerifyError::Item`] or [`VerifyError::Signer`] when an Item of a signed
///   Disclosure fails.
pub fn verify<P: Parameters>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    disclosure: &Disclosure,
    spend_vk: Option<&PreparedSpendVerifyingKey>,
) -> Result<Report, VerifyError> {
    if disclosure.network() != params.network_type() {
        return Err(VerifyError::NetworkMismatch {
            expected: params.network_type(),
            found: disclosure.network(),
        });
    }
    if tx.txid() != disclosure.txid() {
        return Err(VerifyError::TxidMismatch);
    }

    let zip212 = zip212_enforcement(params, height);
    let items: Vec<_> = disclosure
        .items()
        .iter()
        .map(|item| (item.clone(), verify_in_tx(tx, zip212, item)))
        .collect();

    let signed = match disclosure.signing_digest() {
        None => None,
        Some(digest) => {
            let spend_vk = spend_vk.ok_or(VerifyError::MissingSpendVerifyingKey)?;
            let notes = items
                .iter()
                .map(|(item, result)| {
                    result.clone().map_err(|error| VerifyError::Item {
                        kind: item.kind,
                        index: item.index,
                        error,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let signers = disclosure
                .signers()
                .iter()
                .map(|signer| {
                    verify_signer_in_tx(tx, &digest, signer, &notes, spend_vk).map_err(|error| {
                        VerifyError::Signer {
                            kind: signer.body().kind(),
                            error,
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let spend_signers = signers
                .iter()
                .filter(|signer| matches!(signer, SignerStatement::SpendAuthority(_)))
                .count();
            Some(SignedReport {
                signers,
                message: disclosure.message().cloned(),
                inputs_without_signer: input_count(tx) - spend_signers,
            })
        }
    };

    Ok(Report {
        txid: disclosure.txid(),
        class: disclosure.class(),
        items,
        skipped: disclosure
            .unknown_items()
            .iter()
            .map(|u| u.typecode)
            .collect(),
        signed,
    })
}

/// The number of inputs of `tx`, of all pools. Each Orchard or Ironwood action counts as
/// one input.
fn input_count(tx: &Transaction) -> usize {
    tx.transparent_bundle().map_or(0, |b| b.vin.len())
        + tx.sprout_bundle()
            .map_or(0, |b| b.joinsplits.len() * SPROUT_INPUTS_PER_JOINSPLIT)
        + tx.sapling_bundle().map_or(0, |b| b.shielded_spends().len())
        + tx.orchard_bundle().map_or(0, |b| b.actions().len())
        + tx.ironwood_bundle().map_or(0, |b| b.actions().len())
}

fn verify_signer_in_tx(
    tx: &Transaction,
    digest: &[u8; 32],
    signer: &Signer,
    notes: &[DisclosedNote],
    spend_vk: &PreparedSpendVerifyingKey,
) -> Result<SignerStatement, SignerError> {
    match signer.body() {
        SignerBody::SaplingSpend(body) => {
            let bundle = tx.sapling_bundle().ok_or(SignerError::MissingBundle)?;
            let spend = bundle
                .shielded_spends()
                .get(body.index() as usize)
                .ok_or(SignerError::IndexOutOfRange)?;
            verify_spend_signer(spend, digest, signer, spend_vk)
                .map(SignerStatement::SpendAuthority)
        }
        SignerBody::SaplingAddressOwner(_) => {
            let address = verify_address_owner_signer(digest, signer, spend_vk)?;
            let address_bytes = address.to_bytes();
            let outputs: Vec<u32> = notes
                .iter()
                .filter(|note| {
                    note.kind.pool() == Pool::Sapling
                        && address_bytes[..note.diversifier.len()] == note.diversifier
                        && address_bytes[note.diversifier.len()..] == note.pk_d
                })
                .map(|note| note.index)
                .collect();
            if outputs.is_empty() {
                return Err(SignerError::AddressNotDisclosed);
            }
            Ok(SignerStatement::AddressOwner(AddressOwner {
                address,
                outputs,
            }))
        }
    }
}

/// Checks a Sapling spend signer Item (typecode `0xE0` or `0xE1`) against the spend
/// description at its index.
///
/// `digest` is [`Disclosure::signing_digest`] of the Disclosure that holds the Item.
pub fn verify_spend_signer<A: Authorization>(
    spend: &SpendDescription<A>,
    digest: &[u8; 32],
    signer: &Signer,
    spend_vk: &PreparedSpendVerifyingKey,
) -> Result<SpendAuthority, SignerError> {
    let SignerBody::SaplingSpend(body) = signer.body() else {
        return Err(SignerError::WrongKind);
    };
    let cv = ValueCommitment::from_bytes_not_small_order(body.cv())
        .into_option()
        .ok_or(SignerError::InvalidCv)?;
    let (rk, sig) = verify_signature(body.rk(), digest, signer)?;
    verify_spend_proof(
        &SpendStatement {
            cv,
            anchor: *spend.anchor(),
            nullifier: spend.nullifier().0,
            rk,
        },
        body.zkproof(),
        digest,
        sig,
        spend_vk,
    )?;
    let address = body
        .address()
        .map(|proof| verify_address_proof(proof, rk, digest, sig, spend_vk))
        .transpose()?;
    Ok(SpendAuthority {
        index: body.index(),
        address,
    })
}

/// Checks a Sapling address owner signer Item (typecode `0xE2`) and returns the address
/// that its Signer controls.
///
/// The caller checks that the address is the receiver of a Sapling Output Item of the
/// same Disclosure. `digest` is [`Disclosure::signing_digest`] of that Disclosure.
pub fn verify_address_owner_signer(
    digest: &[u8; 32],
    signer: &Signer,
    spend_vk: &PreparedSpendVerifyingKey,
) -> Result<PaymentAddress, SignerError> {
    let SignerBody::SaplingAddressOwner(body) = signer.body() else {
        return Err(SignerError::WrongKind);
    };
    let (rk, sig) = verify_signature(body.rk(), digest, signer)?;
    verify_address_proof(body.address(), rk, digest, sig, spend_vk)
}

/// Decodes `rk` and checks the signature of `signer` over `digest`.
fn verify_signature(
    rk: &[u8; 32],
    digest: &[u8; 32],
    signer: &Signer,
) -> Result<(VerificationKey<SpendAuth>, Signature<SpendAuth>), SignerError> {
    let point = jubjub::AffinePoint::from_bytes(*rk)
        .into_option()
        .ok_or(SignerError::InvalidRk)?;
    if bool::from(point.is_small_order()) {
        return Err(SignerError::InvalidRk);
    }
    let rk = VerificationKey::try_from(*rk).map_err(|_| SignerError::InvalidRk)?;
    let sig = Signature::from(*signer.sig());
    rk.verify(digest, &sig)
        .map_err(|_| SignerError::InvalidSignature)?;
    Ok((rk, sig))
}

/// The primary input of a Sapling Spend statement.
struct SpendStatement {
    cv: ValueCommitment,
    anchor: bls12_381::Scalar,
    nullifier: [u8; 32],
    rk: VerificationKey<SpendAuth>,
}

fn verify_spend_proof(
    statement: &SpendStatement,
    zkproof: &GrothProofBytes,
    digest: &[u8; 32],
    sig: Signature<SpendAuth>,
    spend_vk: &PreparedSpendVerifyingKey,
) -> Result<(), SignerError> {
    let zkproof = groth16::Proof::<Bls12>::read(&zkproof[..])
        .map_err(|_| SignerError::InvalidProofEncoding)?;
    // `check_spend` also checks the signature, which `verify_signature` has accepted.
    if SaplingVerificationContext::new().check_spend(
        &statement.cv,
        statement.anchor,
        &statement.nullifier,
        statement.rk,
        digest,
        sig,
        zkproof,
        spend_vk,
    ) {
        Ok(())
    } else {
        Err(SignerError::InvalidProof)
    }
}

/// Checks the proof of a ZIP 304 signature for the address in `proof`, under `rk`.
fn verify_address_proof(
    proof: &AddressProof,
    rk: VerificationKey<SpendAuth>,
    digest: &[u8; 32],
    sig: Signature<SpendAuth>,
    spend_vk: &PreparedSpendVerifyingKey,
) -> Result<PaymentAddress, SignerError> {
    let mut address = [0; 43];
    address[..proof.diversifier().len()].copy_from_slice(proof.diversifier());
    address[proof.diversifier().len()..].copy_from_slice(proof.pk_d());
    let address = PaymentAddress::from_bytes(&address).ok_or(SignerError::InvalidAddress)?;

    verify_spend_proof(
        &SpendStatement {
            cv: AddressStatement::cv(),
            anchor: AddressStatement::new(address).anchor(),
            nullifier: *proof.nf_addr(),
            rk,
        },
        proof.zkproof(),
        digest,
        sig,
        spend_vk,
    )?;
    Ok(address)
}

fn verify_in_tx(
    tx: &Transaction,
    zip212: Zip212Enforcement,
    item: &Item,
) -> Result<DisclosedNote, ItemError> {
    let index = item.index as usize;
    match item.kind.pool() {
        Pool::Sapling => {
            let bundle = tx.sapling_bundle().ok_or(ItemError::MissingBundle)?;
            let output = bundle
                .shielded_outputs()
                .get(index)
                .ok_or(ItemError::IndexOutOfRange)?;
            verify_sapling_output(output, zip212, item)
        }
        Pool::Orchard => {
            let bundle = tx.orchard_bundle().ok_or(ItemError::MissingBundle)?;
            let action = bundle
                .actions()
                .get(index)
                .ok_or(ItemError::IndexOutOfRange)?;
            verify_action(action, item)
        }
        Pool::Ironwood => {
            let bundle = tx.ironwood_bundle().ok_or(ItemError::MissingBundle)?;
            let action = bundle
                .actions()
                .get(index)
                .ok_or(ItemError::IndexOutOfRange)?;
            verify_action(action, item)
        }
    }
}

fn out_plaintext(pk_d: &[u8; 32], esk: &[u8; 32]) -> OutPlaintextBytes {
    let mut op = [0; OUT_PLAINTEXT_SIZE];
    op[..32].copy_from_slice(pk_d);
    op[32..].copy_from_slice(esk);
    OutPlaintextBytes(op)
}

/// Checks a Sapling Item against one output description.
///
/// `zip212` is the ZIP 212 enforcement at the height of the transaction.
pub fn verify_sapling_output<A>(
    output: &OutputDescription<A>,
    zip212: Zip212Enforcement,
    item: &Item,
) -> Result<DisclosedNote, ItemError> {
    let domain = SaplingDomain::new(zip212);
    let pk_d = SaplingDomain::extract_pk_d(&out_plaintext(&item.pk_d, &[0; 32]))
        .filter(|pk_d| !bool::from(pk_d.inner().is_identity()))
        .ok_or(ItemError::InvalidPkd)?;
    let esk = |bytes: &[u8; 32]| {
        SaplingDomain::extract_esk(&out_plaintext(&item.pk_d, bytes))
            .ok_or(ItemError::InvalidSecret)
    };

    let (note, address, memo) = match item.kind {
        Kind::Sapling => {
            let derived =
                jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_ESK.with(&item.secret)).to_repr();
            let (note, address, memo) =
                try_output_recovery_with_pkd_esk(&domain, pk_d, esk(&derived)?, output)
                    .ok_or(ItemError::Rejected)?;
            if note.rseed() != &Rseed::AfterZip212(item.secret) {
                return Err(ItemError::Rejected);
            }
            (note, address, memo)
        }
        Kind::SaplingLegacySender => {
            let (note, address, memo) =
                try_output_recovery_with_pkd_esk(&domain, pk_d, esk(&item.secret)?, output)
                    .ok_or(ItemError::Rejected)?;
            if !matches!(note.rseed(), Rseed::BeforeZip212(_)) {
                return Err(ItemError::Rejected);
            }
            // For lead byte 0x01 the recovery above does not compare [esk] g_d with epk.
            let epk = SaplingDomain::ka_derive_public(&note, &esk(&item.secret)?);
            if SaplingDomain::epk_bytes(&epk).0 != output.ephemeral_key().0 {
                return Err(ItemError::EphemeralKeyMismatch);
            }
            (note, address, memo)
        }
        Kind::SaplingLegacyReceiver => {
            let (mut plaintext, tag) = output
                .split_ciphertext_at_tag()
                .ok_or(ItemError::Rejected)?;
            ChaCha20Poly1305::new(Key::from_slice(&item.secret))
                .decrypt_in_place_detached(
                    Nonce::from_slice(&[0; 12]),
                    &[],
                    plaintext.as_mut(),
                    Tag::from_slice(&tag),
                )
                .map_err(|_| ItemError::Rejected)?;
            let (compact, memo) = domain
                .split_plaintext_at_memo(&plaintext)
                .ok_or(ItemError::Rejected)?;
            let (note, address) = domain
                .parse_note_plaintext_without_memo_ovk(&pk_d, &compact)
                .ok_or(ItemError::Rejected)?;
            if !matches!(note.rseed(), Rseed::BeforeZip212(_))
                || note.cmu().to_bytes() != output.cmu().to_bytes()
            {
                return Err(ItemError::Rejected);
            }
            (note, address, memo)
        }
        Kind::Orchard | Kind::Ironwood => return Err(ItemError::WrongPool),
    };

    Ok(DisclosedNote {
        kind: item.kind,
        index: item.index,
        diversifier: address.diversifier().0,
        pk_d: item.pk_d,
        value: note.value().inner(),
        memo,
    })
}

/// Checks an Orchard or Ironwood Item against one action of the bundle its kind selects.
pub fn verify_action<T>(action: &Action<T>, item: &Item) -> Result<DisclosedNote, ItemError> {
    match item.kind {
        Kind::Orchard => open_action(OrchardDomain::for_action(action), action, item),
        Kind::Ironwood => open_action(IronwoodDomain::for_action(action), action, item),
        _ => Err(ItemError::WrongPool),
    }
}

fn open_action<D, T>(domain: D, action: &Action<T>, item: &Item) -> Result<DisclosedNote, ItemError>
where
    D: Domain<Note = orchard::Note, Recipient = orchard::Address, Memo = [u8; 512]>,
    Action<T>: ShieldedOutput<D>,
{
    let pk_d =
        D::extract_pk_d(&out_plaintext(&item.pk_d, &[0; 32])).ok_or(ItemError::InvalidPkd)?;
    let derived = pallas::Scalar::from_uniform_bytes(
        &PrfExpand::ORCHARD_ESK.with(&item.secret, &action.rho().to_bytes()),
    )
    .to_repr();
    let esk =
        D::extract_esk(&out_plaintext(&item.pk_d, &derived)).ok_or(ItemError::InvalidSecret)?;

    let (note, address, memo) =
        try_output_recovery_with_pkd_esk(&domain, pk_d, esk, action).ok_or(ItemError::Rejected)?;
    if note.rseed().as_bytes() != &item.secret {
        return Err(ItemError::Rejected);
    }

    Ok(DisclosedNote {
        kind: item.kind,
        index: item.index,
        diversifier: *address.diversifier().as_array(),
        pk_d: item.pk_d,
        value: note.value().inner(),
        memo,
    })
}
