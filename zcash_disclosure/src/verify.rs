//! Verification of a [`Disclosure`] against the transaction it covers.

use std::fmt;

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use ff::{FromUniformBytes, PrimeField};
use group::Group;
use orchard::{
    Action,
    note_encryption::{IronwoodDomain, OrchardDomain},
};
use pasta_curves::pallas;
use sapling::{
    Rseed,
    bundle::OutputDescription,
    note_encryption::{SaplingDomain, Zip212Enforcement},
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

use crate::encoding::{Disclosure, Item, Kind, Pool};

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
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::NetworkMismatch { expected, found } => {
                write!(f, "disclosure is for {found:?}, expected {expected:?}")
            }
            VerifyError::TxidMismatch => write!(f, "the transaction does not match the txid"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// The result of checking a Disclosure, one entry per known Item.
#[derive(Clone, Debug)]
pub struct Report {
    /// The transaction.
    pub txid: TxId,
    /// Each known Item with its result.
    pub items: Vec<(Item, Result<DisclosedNote, ItemError>)>,
    /// The typecodes of the Items the Verifier skipped.
    pub skipped: Vec<u64>,
}

/// Checks `disclosure` against `tx`.
///
/// `height` is the height of the block that contains `tx`, or the height of the next block
/// for a mempool transaction. It sets which note plaintext lead bytes are valid. The caller
/// establishes that `tx` is in a block, how deep, and that its proofs and signatures are
/// valid.
pub fn verify<P: Parameters>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    disclosure: &Disclosure,
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
    let items = disclosure
        .items()
        .iter()
        .map(|item| (item.clone(), verify_in_tx(tx, zip212, item)))
        .collect();
    Ok(Report {
        txid: disclosure.txid(),
        items,
        skipped: disclosure
            .unknown_items()
            .iter()
            .map(|u| u.typecode)
            .collect(),
    })
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
