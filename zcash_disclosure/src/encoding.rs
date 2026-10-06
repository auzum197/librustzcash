//! The string encoding of a [`Disclosure`] and its canonical form.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Cursor, Read};

use bech32::{Bech32m, Checksum, Hrp, primitives::decode::CheckedHrpstring};
use blake2b_simd::Params as Blake2bParams;
use sapling::bundle::GrothProofBytes;
use zcash_encoding::CompactSize;
use zcash_protocol::{
    TxId,
    consensus::{NetworkConstants, NetworkType},
};

/// The payload version this crate reads and writes.
pub const VERSION: u8 = 0x01;

/// The largest number of Items, known and unknown, in one Disclosure.
pub const MAX_ITEMS: usize = 64;

/// The largest Item body, in bytes.
pub const MAX_BODY_LEN: usize = 1024;

/// The largest message of a Message Item, in bytes.
pub const MAX_MESSAGE_LEN: usize = 512;

/// Typecodes in this range must be understood. A decoder rejects a Disclosure that carries
/// one it does not know. This includes the Signer typecodes that the specification
/// reserves for Orchard, Ironwood and transparent inputs.
pub const MUST_UNDERSTAND: core::ops::RangeInclusive<u64> = 0xE0..=0xFF;

/// The typecode of the Message Item.
const MESSAGE_TYPECODE: u8 = 0x10;

const KEY_LEN: usize = 32;
const DIVERSIFIER_LEN: usize = 11;
const ADDRESS_LEN: usize = DIVERSIFIER_LEN + KEY_LEN;
const SIG_LEN: usize = 64;

/// The first 12 bytes of the BLAKE2b personalization of the signature digest. The 4-byte
/// little-endian SLIP-44 coin type follows them.
const DIGEST_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZIP311Signed";
const DIGEST_LEN: usize = 32;

/// Bech32m with the 90-character limit lifted, as ZIP 316 does for Unified Addresses.
enum Bech32mDisclosure {}

impl Checksum for Bech32mDisclosure {
    type MidstateRepr = <Bech32m as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = 4194368;
    const CHECKSUM_LENGTH: usize = Bech32m::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = Bech32m::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = Bech32m::TARGET_RESIDUE;
}

/// The class of a Disclosure. The human-readable part states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Output Items only. A bearer string that a viewing key can produce.
    Unsigned,
    /// Output Items, one or more Signer Items and an optional Message Item. The
    /// signatures cover the full body.
    Signed,
}

const HRPS: [(Class, NetworkType, &str); 6] = [
    (Class::Unsigned, NetworkType::Main, "zdu"),
    (Class::Unsigned, NetworkType::Test, "zdutest"),
    (Class::Unsigned, NetworkType::Regtest, "zduregtest"),
    (Class::Signed, NetworkType::Main, "zds"),
    (Class::Signed, NetworkType::Test, "zdstest"),
    (Class::Signed, NetworkType::Regtest, "zdsregtest"),
];

/// The human-readable part for `class` on `network`.
pub fn hrp(class: Class, network: NetworkType) -> &'static str {
    HRPS.iter()
        .find(|(c, n, _)| *c == class && *n == network)
        .map(|(_, _, hrp)| *hrp)
        .expect("HRPS has an entry for every class and network")
}

fn parse_hrp(hrp: &str) -> Option<(Class, NetworkType)> {
    HRPS.iter()
        .find(|(_, _, h)| *h == hrp)
        .map(|(class, network, _)| (*class, *network))
}

/// The bundle an Item's index points into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pool {
    /// The Sapling outputs of the transaction.
    Sapling,
    /// `vActionsOrchard`.
    Orchard,
    /// `vActionsIronwood`.
    Ironwood,
}

/// The type of an Item, one per known typecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Typecode `0x02`: a Sapling note with lead byte `0x02`. The secret is `rseed`.
    Sapling,
    /// Typecode `0x03`: an Orchard note. The secret is `rseed`.
    Orchard,
    /// Typecode `0x04`: a Sapling note with lead byte `0x01`, disclosed by the sender. The
    /// secret is `esk`.
    SaplingLegacySender,
    /// Typecode `0x05`: a Sapling note with lead byte `0x01`, disclosed by the receiver. The
    /// secret is `K_enc`. Verification of this kind gives no receivability.
    SaplingLegacyReceiver,
    /// Typecode `0x06`: an Ironwood note with lead byte `0x03`. The secret is `rseed`.
    Ironwood,
}

impl Kind {
    /// The typecode of this kind.
    pub fn typecode(self) -> u8 {
        match self {
            Kind::Sapling => 0x02,
            Kind::Orchard => 0x03,
            Kind::SaplingLegacySender => 0x04,
            Kind::SaplingLegacyReceiver => 0x05,
            Kind::Ironwood => 0x06,
        }
    }

    /// The kind for `typecode`, when it is known.
    pub fn from_typecode(typecode: u64) -> Option<Self> {
        match typecode {
            0x02 => Some(Kind::Sapling),
            0x03 => Some(Kind::Orchard),
            0x04 => Some(Kind::SaplingLegacySender),
            0x05 => Some(Kind::SaplingLegacyReceiver),
            0x06 => Some(Kind::Ironwood),
            _ => None,
        }
    }

    /// The bundle this kind's index points into.
    pub fn pool(self) -> Pool {
        match self {
            Kind::Sapling | Kind::SaplingLegacySender | Kind::SaplingLegacyReceiver => {
                Pool::Sapling
            }
            Kind::Orchard => Pool::Orchard,
            Kind::Ironwood => Pool::Ironwood,
        }
    }
}

/// An Output Item: the disclosure of one output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The item type.
    pub kind: Kind,
    /// The position of the output in the bundle that `kind` selects.
    pub index: u32,
    /// The encoding of the receiver's transmission key.
    pub pk_d: [u8; 32],
    /// `rseed`, `esk` or `K_enc`, depending on `kind`.
    pub secret: [u8; 32],
}

impl Item {
    fn body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(5 + 2 * KEY_LEN);
        CompactSize::write(&mut body, self.index as usize).expect("writes to a Vec do not fail");
        body.extend_from_slice(&self.pk_d);
        body.extend_from_slice(&self.secret);
        body
    }

    fn parse(kind: Kind, body: &[u8]) -> Result<Self, FormatError> {
        let mut reader = Cursor::new(body);
        let index = read_compact(&mut reader)?;
        let index = u32::try_from(index).map_err(|_| FormatError::IndexOutOfRange)?;
        let rest = &body[reader.position() as usize..];
        if rest.len() != 2 * KEY_LEN {
            return Err(FormatError::LengthMismatch {
                typecode: kind.typecode(),
            });
        }
        let (pk_d, secret) = rest.split_at(KEY_LEN);
        Ok(Item {
            kind,
            index,
            pk_d: pk_d.try_into().expect("split at KEY_LEN"),
            secret: secret.try_into().expect("remainder is KEY_LEN"),
        })
    }
}

/// An Item whose typecode this crate does not know. It is kept so the Disclosure re-encodes
/// to the same string, and a Verifier reports it as skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownItem {
    /// The Item's typecode.
    pub typecode: u64,
    /// The Item's body.
    pub body: Vec<u8>,
}

/// The message of a Message Item. The signatures of a signed Disclosure bind it.
///
/// The format gives the bytes no structure. They can hold text or a challenge from the
/// Verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message(Vec<u8>);

impl Message {
    /// Builds a message of 1 to [`MAX_MESSAGE_LEN`] bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FormatError> {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE_LEN {
            return Err(FormatError::LengthMismatch {
                typecode: MESSAGE_TYPECODE,
            });
        }
        Ok(Message(bytes))
    }

    /// The message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The message as text, when it is valid UTF-8.
    pub fn as_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

/// The type of a Signer Item, one per known Signer typecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignerKind {
    /// Typecode `0xE0`: a holder of the spending key of a Sapling spend.
    SaplingSpend,
    /// Typecode `0xE1`: the same, with a proof of the Signer's payment address.
    SaplingSpendWithAddress,
    /// Typecode `0xE2`: the owner of the receiver address of a disclosed Sapling output.
    SaplingAddressOwner,
}

impl SignerKind {
    /// The typecode of this kind.
    pub fn typecode(self) -> u8 {
        match self {
            SignerKind::SaplingSpend => 0xE0,
            SignerKind::SaplingSpendWithAddress => 0xE1,
            SignerKind::SaplingAddressOwner => 0xE2,
        }
    }

    /// The kind for `typecode`, when it is known.
    pub fn from_typecode(typecode: u64) -> Option<Self> {
        match typecode {
            0xE0 => Some(SignerKind::SaplingSpend),
            0xE1 => Some(SignerKind::SaplingSpendWithAddress),
            0xE2 => Some(SignerKind::SaplingAddressOwner),
            _ => None,
        }
    }
}

/// The proof that a Signer controls a Sapling payment address: the proof of a [ZIP 304]
/// signature, without the signature.
///
/// [ZIP 304]: https://zips.z.cash/zip-0304
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressProof {
    pub(crate) diversifier: [u8; DIVERSIFIER_LEN],
    pub(crate) pk_d: [u8; KEY_LEN],
    pub(crate) nf_addr: [u8; KEY_LEN],
    pub(crate) zkproof: GrothProofBytes,
}

impl AddressProof {
    /// The diversifier of the address.
    pub fn diversifier(&self) -> &[u8; DIVERSIFIER_LEN] {
        &self.diversifier
    }

    /// The encoding of the transmission key of the address.
    pub fn pk_d(&self) -> &[u8; KEY_LEN] {
        &self.pk_d
    }

    /// The nullifier of the ZIP 304 note of the address. It is the same in every proof
    /// for one address.
    pub fn nf_addr(&self) -> &[u8; KEY_LEN] {
        &self.nf_addr
    }

    /// The encoding of the Sapling spend proof for the ZIP 304 note.
    pub fn zkproof(&self) -> &GrothProofBytes {
        &self.zkproof
    }

    fn address_bytes(&self) -> [u8; ADDRESS_LEN] {
        let mut bytes = [0; ADDRESS_LEN];
        bytes[..DIVERSIFIER_LEN].copy_from_slice(&self.diversifier);
        bytes[DIVERSIFIER_LEN..].copy_from_slice(&self.pk_d);
        bytes
    }

    fn write_address_and_nf(&self, body: &mut Vec<u8>) {
        body.extend_from_slice(&self.diversifier);
        body.extend_from_slice(&self.pk_d);
        body.extend_from_slice(&self.nf_addr);
    }

    fn read_address_and_nf(fields: &mut Fields<'_>) -> Option<([u8; 11], [u8; 32], [u8; 32])> {
        Some((fields.take()?, fields.take()?, fields.take()?))
    }
}

/// The fields of a Sapling spend signer Item (typecodes `0xE0` and `0xE1`) before its
/// signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendSigner {
    pub(crate) index: u32,
    pub(crate) cv: [u8; KEY_LEN],
    pub(crate) rk: [u8; KEY_LEN],
    pub(crate) zkproof: GrothProofBytes,
    pub(crate) address: Option<AddressProof>,
}

impl SpendSigner {
    /// The position of the spend in the Sapling spends of the transaction.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The encoding of the value commitment of the Signer's spend proof.
    pub fn cv(&self) -> &[u8; KEY_LEN] {
        &self.cv
    }

    /// The encoding of the randomized key that validates the signature.
    pub fn rk(&self) -> &[u8; KEY_LEN] {
        &self.rk
    }

    /// The encoding of the Signer's Sapling spend proof.
    pub fn zkproof(&self) -> &GrothProofBytes {
        &self.zkproof
    }

    /// The proof of the Signer's payment address, for typecode `0xE1`.
    pub fn address(&self) -> Option<&AddressProof> {
        self.address.as_ref()
    }
}

/// The fields of a Sapling address owner signer Item (typecode `0xE2`) before its
/// signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressOwnerSigner {
    pub(crate) address: AddressProof,
    pub(crate) rk: [u8; KEY_LEN],
}

impl AddressOwnerSigner {
    /// The proof of the receiver address.
    pub fn address(&self) -> &AddressProof {
        &self.address
    }

    /// The encoding of the randomized key that validates the signature.
    pub fn rk(&self) -> &[u8; KEY_LEN] {
        &self.rk
    }
}

/// The fields of a Signer Item before its signature. The signature digest covers them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SignerBody {
    /// Typecodes `0xE0` and `0xE1`.
    SaplingSpend(SpendSigner),
    /// Typecode `0xE2`.
    SaplingAddressOwner(AddressOwnerSigner),
}

impl SignerBody {
    /// The type of the Signer Item.
    pub fn kind(&self) -> SignerKind {
        match self {
            SignerBody::SaplingSpend(spend) if spend.address.is_some() => {
                SignerKind::SaplingSpendWithAddress
            }
            SignerBody::SaplingSpend(_) => SignerKind::SaplingSpend,
            SignerBody::SaplingAddressOwner(_) => SignerKind::SaplingAddressOwner,
        }
    }

    /// The encoding of the randomized key that validates the signature.
    pub fn rk(&self) -> &[u8; KEY_LEN] {
        match self {
            SignerBody::SaplingSpend(spend) => &spend.rk,
            SignerBody::SaplingAddressOwner(owner) => &owner.rk,
        }
    }

    fn key(&self) -> Key {
        match self {
            SignerBody::SaplingSpend(spend) => Key::Index(spend.index),
            SignerBody::SaplingAddressOwner(owner) => Key::Address(owner.address.address_bytes()),
        }
    }

    /// The Item body without the trailing signature.
    fn fields(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(MAX_BODY_LEN);
        match self {
            SignerBody::SaplingSpend(spend) => {
                CompactSize::write(&mut body, spend.index as usize)
                    .expect("writes to a Vec do not fail");
                body.extend_from_slice(&spend.cv);
                body.extend_from_slice(&spend.rk);
                body.extend_from_slice(&spend.zkproof);
                if let Some(address) = &spend.address {
                    address.write_address_and_nf(&mut body);
                    body.extend_from_slice(&address.zkproof);
                }
            }
            SignerBody::SaplingAddressOwner(owner) => {
                owner.address.write_address_and_nf(&mut body);
                body.extend_from_slice(&owner.rk);
                body.extend_from_slice(&owner.address.zkproof);
            }
        }
        body
    }

    fn parse(kind: SignerKind, body: &[u8]) -> Result<(Self, [u8; SIG_LEN]), FormatError> {
        let mismatch = FormatError::LengthMismatch {
            typecode: kind.typecode(),
        };
        let (index, rest) = match kind {
            SignerKind::SaplingAddressOwner => (None, body),
            SignerKind::SaplingSpend | SignerKind::SaplingSpendWithAddress => {
                let mut reader = Cursor::new(body);
                let index = read_compact(&mut reader)?;
                let index = u32::try_from(index).map_err(|_| FormatError::IndexOutOfRange)?;
                (Some(index), &body[reader.position() as usize..])
            }
        };

        let mut fields = Fields(rest);
        let parsed = match index {
            Some(index) => (|| {
                let cv = fields.take()?;
                let rk = fields.take()?;
                let zkproof = fields.take()?;
                let address = match kind {
                    SignerKind::SaplingSpendWithAddress => {
                        let (diversifier, pk_d, nf_addr) =
                            AddressProof::read_address_and_nf(&mut fields)?;
                        Some(AddressProof {
                            diversifier,
                            pk_d,
                            nf_addr,
                            zkproof: fields.take()?,
                        })
                    }
                    _ => None,
                };
                let body = SignerBody::SaplingSpend(SpendSigner {
                    index,
                    cv,
                    rk,
                    zkproof,
                    address,
                });
                Some((body, fields.take()?))
            })(),
            None => (|| {
                let (diversifier, pk_d, nf_addr) = AddressProof::read_address_and_nf(&mut fields)?;
                let rk = fields.take()?;
                let body = SignerBody::SaplingAddressOwner(AddressOwnerSigner {
                    address: AddressProof {
                        diversifier,
                        pk_d,
                        nf_addr,
                        zkproof: fields.take()?,
                    },
                    rk,
                });
                Some((body, fields.take()?))
            })(),
        };
        match parsed {
            Some(parsed) if fields.0.is_empty() => Ok(parsed),
            _ => Err(mismatch),
        }
    }
}

/// A Signer Item: a proof and a signature by a party that holds a spending key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    pub(crate) body: SignerBody,
    pub(crate) sig: [u8; SIG_LEN],
}

impl Signer {
    /// The fields that the signature digest covers.
    pub fn body(&self) -> &SignerBody {
        &self.body
    }

    /// The encoding of the signature over the digest of the Disclosure.
    pub fn sig(&self) -> &[u8; SIG_LEN] {
        &self.sig
    }
}

/// The remaining bytes of an Item body with fixed-size fields.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }
}

/// The part of an Item that orders it among Items with the same typecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    None,
    Index(u32),
    Address([u8; ADDRESS_LEN]),
}

/// One Item of a payload: its fields, and its signature when it is a Signer Item.
struct Entry {
    typecode: u64,
    key: Key,
    fields: Vec<u8>,
    sig: Option<[u8; SIG_LEN]>,
}

/// The disclosure of a set of shielded outputs of one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    class: Class,
    network: NetworkType,
    txid: TxId,
    items: Vec<Item>,
    message: Option<Message>,
    signers: Vec<Signer>,
    unknown: Vec<UnknownItem>,
}

/// A violation of the encoding or of its canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The string is not valid Bech32m.
    InvalidBech32m,
    /// The string contains uppercase characters. The canonical form is lowercase.
    Uppercase,
    /// The human-readable part is not a Disclosure HRP.
    UnknownHrp(String),
    /// The Bech32m padding is longer than 4 bits or not zero.
    InvalidPadding,
    /// The payload version is not [`VERSION`].
    UnknownVersion(u8),
    /// The payload ends inside a field.
    Truncated,
    /// A CompactSize does not use its shortest encoding.
    NonCanonicalCompactSize,
    /// A known Item's body has the wrong length.
    LengthMismatch {
        /// The Item's typecode.
        typecode: u8,
    },
    /// An Item's index does not fit in 32 bits.
    IndexOutOfRange,
    /// An Item body exceeds [`MAX_BODY_LEN`].
    BodyTooLong,
    /// The Disclosure has more than [`MAX_ITEMS`] Items.
    TooManyItems,
    /// Items are not strictly increasing by `(typecode, key)`.
    NotSorted,
    /// Two Items point at the same output.
    DuplicateOutput {
        /// The bundle.
        pool: Pool,
        /// The index in the bundle.
        index: u32,
    },
    /// Two Signer Items point at the same Sapling spend.
    DuplicateSpend {
        /// The index in the Sapling spends.
        index: u32,
    },
    /// Two address owner Signer Items are for the same address.
    DuplicateAddressOwner,
    /// An unsigned Disclosure has no Output Item with a known typecode.
    NoKnownItems,
    /// A signed Disclosure has no Signer Item.
    NoSigners,
    /// An unsigned Disclosure has a Message Item or a Signer Item.
    SignedItemInUnsigned {
        /// The Item's typecode.
        typecode: u8,
    },
    /// The Disclosure has an unknown typecode in the [`MUST_UNDERSTAND`] range.
    UnknownMustUnderstand(u64),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::InvalidBech32m => write!(f, "not a valid Bech32m string"),
            FormatError::Uppercase => write!(f, "uppercase characters are not canonical"),
            FormatError::UnknownHrp(hrp) => write!(f, "unknown human-readable part: {hrp}"),
            FormatError::InvalidPadding => write!(f, "invalid Bech32m padding"),
            FormatError::UnknownVersion(v) => write!(f, "unknown disclosure version {v:#04x}"),
            FormatError::Truncated => write!(f, "payload ends inside a field"),
            FormatError::NonCanonicalCompactSize => write!(f, "non-canonical CompactSize"),
            FormatError::LengthMismatch { typecode } => {
                write!(f, "wrong body length for typecode {typecode:#04x}")
            }
            FormatError::IndexOutOfRange => write!(f, "index does not fit in 32 bits"),
            FormatError::BodyTooLong => write!(f, "item body exceeds {MAX_BODY_LEN} bytes"),
            FormatError::TooManyItems => write!(f, "more than {MAX_ITEMS} items"),
            FormatError::NotSorted => write!(f, "items are not sorted by (typecode, key)"),
            FormatError::DuplicateOutput { pool, index } => {
                write!(f, "output {index} of the {pool:?} bundle appears twice")
            }
            FormatError::DuplicateSpend { index } => {
                write!(f, "Sapling spend {index} has two signer items")
            }
            FormatError::DuplicateAddressOwner => {
                write!(f, "an address has two address owner signer items")
            }
            FormatError::NoKnownItems => write!(f, "no output item with a known typecode"),
            FormatError::NoSigners => write!(f, "a signed disclosure has no signer item"),
            FormatError::SignedItemInUnsigned { typecode } => write!(
                f,
                "typecode {typecode:#04x} is not valid in an unsigned disclosure"
            ),
            FormatError::UnknownMustUnderstand(t) => {
                write!(f, "unknown must-understand typecode {t:#x}")
            }
        }
    }
}

impl std::error::Error for FormatError {}

fn read_compact<R: Read>(reader: &mut R) -> Result<u64, FormatError> {
    CompactSize::read(reader).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => FormatError::Truncated,
        _ => FormatError::NonCanonicalCompactSize,
    })
}

/// Checks the rules of the canonical form that do not depend on the order of the Items.
fn check_items(
    class: Class,
    items: &[Item],
    message: Option<&Message>,
    signers: &[Signer],
    unknown: &[UnknownItem],
) -> Result<(), FormatError> {
    let count = items.len() + usize::from(message.is_some()) + signers.len() + unknown.len();
    if count > MAX_ITEMS {
        return Err(FormatError::TooManyItems);
    }

    let mut outputs = BTreeSet::new();
    for item in items {
        if !outputs.insert((item.kind.pool(), item.index)) {
            return Err(FormatError::DuplicateOutput {
                pool: item.kind.pool(),
                index: item.index,
            });
        }
    }
    let mut signer_keys = BTreeSet::new();
    for signer in signers {
        if !signer_keys.insert(signer.body.key()) {
            return Err(match &signer.body {
                SignerBody::SaplingSpend(spend) => {
                    FormatError::DuplicateSpend { index: spend.index }
                }
                SignerBody::SaplingAddressOwner(_) => FormatError::DuplicateAddressOwner,
            });
        }
    }

    match class {
        Class::Unsigned => {
            if let Some(signer) = signers.first() {
                return Err(FormatError::SignedItemInUnsigned {
                    typecode: signer.body.kind().typecode(),
                });
            }
            if message.is_some() {
                return Err(FormatError::SignedItemInUnsigned {
                    typecode: MESSAGE_TYPECODE,
                });
            }
            if items.is_empty() {
                return Err(FormatError::NoKnownItems);
            }
        }
        Class::Signed => {
            if signers.is_empty() {
                return Err(FormatError::NoSigners);
            }
        }
    }
    Ok(())
}

impl Disclosure {
    /// Builds an unsigned Disclosure from Output Items. The Items are sorted into
    /// canonical order.
    pub fn new(
        network: NetworkType,
        txid: TxId,
        mut items: Vec<Item>,
    ) -> Result<Self, FormatError> {
        check_items(Class::Unsigned, &items, None, &[], &[])?;
        items.sort_by_key(|item| (item.kind.typecode(), item.index));
        Ok(Disclosure {
            class: Class::Unsigned,
            network,
            txid,
            items,
            message: None,
            signers: vec![],
            unknown: vec![],
        })
    }

    /// Builds a signed Disclosure. The Items are sorted into canonical order. The caller
    /// makes sure that each signature is over [`Disclosure::signing_digest`].
    pub(crate) fn signed(
        network: NetworkType,
        txid: TxId,
        mut items: Vec<Item>,
        message: Option<Message>,
        mut signers: Vec<Signer>,
    ) -> Result<Self, FormatError> {
        check_items(Class::Signed, &items, message.as_ref(), &signers, &[])?;
        items.sort_by_key(|item| (item.kind.typecode(), item.index));
        signers.sort_by_key(|signer| (signer.body.kind().typecode(), signer.body.key()));
        Ok(Disclosure {
            class: Class::Signed,
            network,
            txid,
            items,
            message,
            signers,
            unknown: vec![],
        })
    }

    /// The class the HRP states.
    pub fn class(&self) -> Class {
        self.class
    }

    /// The network the HRP binds this Disclosure to.
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// The transaction this Disclosure covers.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// The Output Items with known typecodes, in canonical order.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The message that the signatures bind. An unsigned Disclosure has none.
    pub fn message(&self) -> Option<&Message> {
        self.message.as_ref()
    }

    /// The Signer Items, in canonical order. An unsigned Disclosure has none.
    pub fn signers(&self) -> &[Signer] {
        &self.signers
    }

    /// The Items with unknown typecodes, in the order they were decoded.
    pub fn unknown_items(&self) -> &[UnknownItem] {
        &self.unknown
    }

    pub(crate) fn signers_mut(&mut self) -> &mut [Signer] {
        &mut self.signers
    }

    /// The digest that every Signer Item signs. An unsigned Disclosure has none.
    ///
    /// The digest covers the HRP, the version, the txid and every Item, without the
    /// signature bytes of the Signer Items.
    pub fn signing_digest(&self) -> Option<[u8; DIGEST_LEN]> {
        match self.class {
            Class::Unsigned => None,
            Class::Signed => {
                let hrp = hrp(self.class, self.network);
                let mut personalization = [0; 16];
                personalization[..DIGEST_PERSONALIZATION_PREFIX.len()]
                    .copy_from_slice(DIGEST_PERSONALIZATION_PREFIX);
                personalization[DIGEST_PERSONALIZATION_PREFIX.len()..]
                    .copy_from_slice(&self.network.coin_type().to_le_bytes());

                let mut hrp_len = vec![];
                CompactSize::write(&mut hrp_len, hrp.len()).expect("writes to a Vec do not fail");

                let digest = Blake2bParams::new()
                    .hash_length(DIGEST_LEN)
                    .personal(&personalization)
                    .to_state()
                    .update(&hrp_len)
                    .update(hrp.as_bytes())
                    .update(&self.payload(SignatureBytes::Omit))
                    .finalize();
                Some(digest.as_bytes().try_into().expect("32-byte digest"))
            }
        }
    }

    fn entries(&self) -> Vec<Entry> {
        let outputs = self.items.iter().map(|item| Entry {
            typecode: u64::from(item.kind.typecode()),
            key: Key::Index(item.index),
            fields: item.body(),
            sig: None,
        });
        let message = self.message.iter().map(|message| Entry {
            typecode: u64::from(MESSAGE_TYPECODE),
            key: Key::None,
            fields: message.0.clone(),
            sig: None,
        });
        let signers = self.signers.iter().map(|signer| Entry {
            typecode: u64::from(signer.body.kind().typecode()),
            key: signer.body.key(),
            fields: signer.body.fields(),
            sig: Some(signer.sig),
        });
        let unknown = self.unknown.iter().map(|u| Entry {
            typecode: u.typecode,
            key: Key::None,
            fields: u.body.clone(),
            sig: None,
        });
        let mut entries: Vec<Entry> = outputs
            .chain(message)
            .chain(signers)
            .chain(unknown)
            .collect();
        entries.sort_by_key(|entry| (entry.typecode, entry.key));
        entries
    }

    /// The payload. `length` of a Signer Item counts its signature in both modes.
    fn payload(&self, signatures: SignatureBytes) -> Vec<u8> {
        let mut payload = vec![VERSION];
        payload.extend_from_slice(self.txid.as_ref());
        for entry in self.entries() {
            let sig_len = entry.sig.map_or(0, |sig| sig.len());
            CompactSize::write(&mut payload, entry.typecode as usize)
                .expect("writes to a Vec do not fail");
            CompactSize::write(&mut payload, entry.fields.len() + sig_len)
                .expect("writes to a Vec do not fail");
            payload.extend_from_slice(&entry.fields);
            if let (SignatureBytes::Include, Some(sig)) = (signatures, entry.sig) {
                payload.extend_from_slice(&sig);
            }
        }
        payload
    }

    /// Encodes this Disclosure as a lowercase Bech32m string.
    pub fn encode(&self) -> String {
        bech32::encode::<Bech32mDisclosure>(
            Hrp::parse_unchecked(hrp(self.class, self.network)),
            &self.payload(SignatureBytes::Include),
        )
        .expect("MAX_ITEMS and MAX_BODY_LEN bound the length below CODE_LENGTH")
    }

    /// Decodes a Disclosure string of either class and enforces the canonical form.
    pub fn decode(s: &str) -> Result<Self, FormatError> {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(FormatError::Uppercase);
        }
        let parsed = CheckedHrpstring::new::<Bech32mDisclosure>(s)
            .map_err(|_| FormatError::InvalidBech32m)?;
        let (class, network) = parse_hrp(parsed.hrp().as_str())
            .ok_or_else(|| FormatError::UnknownHrp(parsed.hrp().to_string()))?;
        parsed
            .validate_segwit_padding()
            .map_err(|_| FormatError::InvalidPadding)?;
        let payload: Vec<u8> = parsed.byte_iter().collect();
        Self::parse_payload(class, network, &payload)
    }

    fn parse_payload(
        class: Class,
        network: NetworkType,
        payload: &[u8],
    ) -> Result<Self, FormatError> {
        let mut reader = Cursor::new(payload);
        let mut version = [0; 1];
        reader
            .read_exact(&mut version)
            .map_err(|_| FormatError::Truncated)?;
        if version[0] != VERSION {
            return Err(FormatError::UnknownVersion(version[0]));
        }
        let mut txid = [0; 32];
        reader
            .read_exact(&mut txid)
            .map_err(|_| FormatError::Truncated)?;

        let mut items = vec![];
        let mut message = None;
        let mut signers = vec![];
        let mut unknown = vec![];
        let mut count = 0;
        let mut last: Option<(u64, Option<Key>)> = None;
        while (reader.position() as usize) < payload.len() {
            if count == MAX_ITEMS {
                return Err(FormatError::TooManyItems);
            }
            count += 1;
            let typecode = read_compact(&mut reader)?;
            let len = read_compact(&mut reader)?;
            if len > MAX_BODY_LEN as u64 {
                return Err(FormatError::BodyTooLong);
            }
            let mut body = vec![0; len as usize];
            reader
                .read_exact(&mut body)
                .map_err(|_| FormatError::Truncated)?;

            // The key of a known Item. An unknown Item has no key and no order among the
            // Items of its typecode.
            let key = if let Some(kind) = Kind::from_typecode(typecode) {
                let item = Item::parse(kind, &body)?;
                let key = Key::Index(item.index);
                items.push(item);
                Some(key)
            } else if typecode == u64::from(MESSAGE_TYPECODE) {
                message = Some(Message::new(body)?);
                Some(Key::None)
            } else if let Some(kind) = SignerKind::from_typecode(typecode) {
                let (body, sig) = SignerBody::parse(kind, &body)?;
                let key = body.key();
                signers.push(Signer { body, sig });
                Some(key)
            } else if MUST_UNDERSTAND.contains(&typecode) {
                return Err(FormatError::UnknownMustUnderstand(typecode));
            } else {
                unknown.push(UnknownItem { typecode, body });
                None
            };

            if let Some((last_typecode, last_key)) = last {
                let ordered = match (last_key, key) {
                    (Some(a), Some(b)) if last_typecode == typecode => a < b,
                    _ => last_typecode <= typecode,
                };
                if !ordered {
                    return Err(FormatError::NotSorted);
                }
            }
            last = Some((typecode, key));
        }

        check_items(class, &items, message.as_ref(), &signers, &unknown)?;
        Ok(Disclosure {
            class,
            network,
            txid: TxId::from_bytes(txid),
            items,
            message,
            signers,
            unknown,
        })
    }
}

/// Whether a payload carries the signature bytes of its Signer Items.
#[derive(Clone, Copy)]
enum SignatureBytes {
    Include,
    Omit,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 32] = [7; 32];

    fn item(kind: Kind, index: u32) -> Item {
        Item {
            kind,
            index,
            pk_d: [index as u8; 32],
            secret: [0xab; 32],
        }
    }

    fn sample() -> Disclosure {
        Disclosure::new(
            NetworkType::Main,
            TxId::from_bytes(TXID),
            vec![
                item(Kind::Orchard, 3),
                item(Kind::Sapling, 1),
                item(Kind::Orchard, 0),
            ],
        )
        .unwrap()
    }

    fn address_proof(seed: u8) -> AddressProof {
        AddressProof {
            diversifier: [seed; 11],
            pk_d: [seed; 32],
            nf_addr: [seed.wrapping_add(1); 32],
            zkproof: [seed.wrapping_add(2); 192],
        }
    }

    /// A spend signer Item with arbitrary bytes. Decoding does not check them.
    fn spend_signer(index: u32, address: Option<AddressProof>) -> Signer {
        Signer {
            body: SignerBody::SaplingSpend(SpendSigner {
                index,
                cv: [0x11; 32],
                rk: [0x22; 32],
                zkproof: [0x33; 192],
                address,
            }),
            sig: [0x44; 64],
        }
    }

    fn owner_signer(seed: u8) -> Signer {
        Signer {
            body: SignerBody::SaplingAddressOwner(AddressOwnerSigner {
                address: address_proof(seed),
                rk: [0x55; 32],
            }),
            sig: [0x66; 64],
        }
    }

    fn message(text: &str) -> Message {
        Message::new(text.as_bytes().to_vec()).unwrap()
    }

    fn signed_sample() -> Disclosure {
        Disclosure::signed(
            NetworkType::Main,
            TxId::from_bytes(TXID),
            vec![item(Kind::Sapling, 1)],
            Some(message("invoice 7")),
            vec![
                owner_signer(9),
                spend_signer(2, Some(address_proof(5))),
                spend_signer(0, None),
            ],
        )
        .unwrap()
    }

    fn encode_payload(hrp: &str, payload: &[u8]) -> String {
        bech32::encode::<Bech32mDisclosure>(Hrp::parse_unchecked(hrp), payload).unwrap()
    }

    fn with_payload(f: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut payload = sample().payload(SignatureBytes::Include);
        f(&mut payload);
        encode_payload("zdu", &payload)
    }

    #[test]
    fn round_trip() {
        let d = sample();
        let s = d.encode();
        assert!(s.starts_with("zdu1"));
        assert_eq!(Disclosure::decode(&s), Ok(d.clone()));
        assert_eq!(d.class(), Class::Unsigned);
        assert_eq!(
            d.items()
                .iter()
                .map(|i| (i.kind, i.index))
                .collect::<Vec<_>>(),
            vec![(Kind::Sapling, 1), (Kind::Orchard, 0), (Kind::Orchard, 3)]
        );
    }

    #[test]
    fn hrp_selects_network() {
        let d = Disclosure::new(
            NetworkType::Test,
            TxId::from_bytes([1; 32]),
            vec![item(Kind::Ironwood, 0)],
        )
        .unwrap();
        let s = d.encode();
        assert!(s.starts_with("zdutest1"));
        assert_eq!(Disclosure::decode(&s).unwrap().network(), NetworkType::Test);
    }

    #[test]
    fn signed_round_trip_keeps_canonical_order() {
        let d = signed_sample();
        let s = d.encode();
        assert!(s.starts_with("zds1"));
        let decoded = Disclosure::decode(&s).unwrap();
        assert_eq!(decoded, d);
        assert_eq!(decoded.class(), Class::Signed);
        assert_eq!(decoded.message(), Some(&message("invoice 7")));
        assert_eq!(
            decoded
                .signers()
                .iter()
                .map(|signer| signer.body().kind())
                .collect::<Vec<_>>(),
            vec![
                SignerKind::SaplingSpend,
                SignerKind::SaplingSpendWithAddress,
                SignerKind::SaplingAddressOwner,
            ]
        );
    }

    #[test]
    fn signed_disclosure_can_have_no_output_items() {
        let d = Disclosure::signed(
            NetworkType::Regtest,
            TxId::from_bytes(TXID),
            vec![],
            None,
            vec![spend_signer(0, None)],
        )
        .unwrap();
        let s = d.encode();
        assert!(s.starts_with("zdsregtest1"));
        assert_eq!(Disclosure::decode(&s), Ok(d));
    }

    #[test]
    fn rejects_uppercase() {
        let s = sample().encode().to_uppercase();
        assert_eq!(Disclosure::decode(&s), Err(FormatError::Uppercase));
    }

    #[test]
    fn rejects_unknown_hrp() {
        let s = encode_payload("zdisc", &sample().payload(SignatureBytes::Include));
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::UnknownHrp("zdisc".into()))
        );
    }

    #[test]
    fn rejects_same_output_under_two_sapling_typecodes() {
        let err = Disclosure::new(
            NetworkType::Main,
            TxId::from_bytes([0; 32]),
            vec![
                item(Kind::SaplingLegacySender, 2),
                item(Kind::SaplingLegacyReceiver, 2),
            ],
        );
        assert_eq!(
            err,
            Err(FormatError::DuplicateOutput {
                pool: Pool::Sapling,
                index: 2
            })
        );
    }

    #[test]
    fn rejects_unsorted_items() {
        // The first two items are Sapling #1 and Orchard #0. Swap their typecodes' order by
        // moving the Orchard item in front.
        let s = with_payload(|p| {
            let item_len = 1 + 1 + 1 + 64;
            let sapling: Vec<u8> = p[33..33 + item_len].to_vec();
            let orchard: Vec<u8> = p[33 + item_len..33 + 2 * item_len].to_vec();
            p[33..33 + item_len].copy_from_slice(&orchard);
            p[33 + item_len..33 + 2 * item_len].copy_from_slice(&sapling);
        });
        assert_eq!(Disclosure::decode(&s), Err(FormatError::NotSorted));
    }

    #[test]
    fn rejects_trailing_body_bytes() {
        let s = with_payload(|p| {
            p[34] += 1;
            p.push(0);
        });
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::LengthMismatch { typecode: 0x02 })
        );
    }

    #[test]
    fn rejects_non_canonical_compact_size() {
        let s = with_payload(|p| {
            // Rewrite the first typecode 0x02 as 0xfd 0x02 0x00.
            p.splice(33..34, [0xfd, 0x02, 0x00]);
        });
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::NonCanonicalCompactSize)
        );
    }

    #[test]
    fn rejects_truncated_payload() {
        let s = with_payload(|p| {
            p.pop();
        });
        assert_eq!(Disclosure::decode(&s), Err(FormatError::Truncated));
    }

    #[test]
    fn skips_and_keeps_unknown_typecodes() {
        let s = with_payload(|p| p.extend_from_slice(&[0x20, 0x02, 0xaa, 0xbb]));
        let d = Disclosure::decode(&s).unwrap();
        assert_eq!(
            d.unknown_items(),
            &[UnknownItem {
                typecode: 0x20,
                body: vec![0xaa, 0xbb]
            }]
        );
        assert_eq!(d.encode(), s);
    }

    #[test]
    fn rejects_reserved_signer_typecode() {
        // 0xe3 is in the range that the specification reserves for Orchard, Ironwood and
        // transparent Signer Items.
        let mut payload = signed_sample().payload(SignatureBytes::Include);
        payload.extend_from_slice(&[0xe3, 0x00]);
        assert_eq!(
            Disclosure::decode(&encode_payload("zds", &payload)),
            Err(FormatError::UnknownMustUnderstand(0xe3))
        );
    }

    #[test]
    fn rejects_disclosure_without_known_items() {
        let mut payload = vec![VERSION];
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&[0x20, 0x00]);
        assert_eq!(
            Disclosure::decode(&encode_payload("zdu", &payload)),
            Err(FormatError::NoKnownItems)
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let s = with_payload(|p| p[0] = 0x02);
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::UnknownVersion(0x02))
        );
    }

    #[test]
    fn unsigned_class_rejects_message_and_signer_items() {
        let payload = signed_sample().payload(SignatureBytes::Include);
        assert_eq!(
            Disclosure::decode(&encode_payload("zdu", &payload)),
            Err(FormatError::SignedItemInUnsigned { typecode: 0xe0 })
        );

        let s = with_payload(|p| p.extend_from_slice(&[0x10, 0x02, b'h', b'i']));
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::SignedItemInUnsigned { typecode: 0x10 })
        );
    }

    #[test]
    fn signed_class_requires_a_signer_item() {
        let payload = sample().payload(SignatureBytes::Include);
        assert_eq!(
            Disclosure::decode(&encode_payload("zds", &payload)),
            Err(FormatError::NoSigners)
        );
        assert_eq!(
            Disclosure::signed(
                NetworkType::Main,
                TxId::from_bytes(TXID),
                vec![item(Kind::Sapling, 0)],
                None,
                vec![],
            ),
            Err(FormatError::NoSigners)
        );
    }

    #[test]
    fn rejects_two_signer_items_for_one_spend_or_address() {
        let signed = |signers| {
            Disclosure::signed(
                NetworkType::Main,
                TxId::from_bytes(TXID),
                vec![],
                None,
                signers,
            )
        };
        assert_eq!(
            signed(vec![
                spend_signer(1, None),
                spend_signer(1, Some(address_proof(5)))
            ]),
            Err(FormatError::DuplicateSpend { index: 1 })
        );
        assert_eq!(
            signed(vec![owner_signer(9), owner_signer(9)]),
            Err(FormatError::DuplicateAddressOwner)
        );
    }

    #[test]
    fn rejects_message_outside_its_size_limits() {
        let mismatch = Err(FormatError::LengthMismatch { typecode: 0x10 });
        assert_eq!(Message::new(vec![]), mismatch);
        assert_eq!(Message::new(vec![0; MAX_MESSAGE_LEN + 1]), mismatch);
        assert!(Message::new(vec![0; MAX_MESSAGE_LEN]).is_ok());

        // An empty Message Item in front of the spend signer Item.
        let mut payload = vec![VERSION];
        payload.extend_from_slice(&TXID);
        payload.extend_from_slice(&[0x10, 0x00]);
        assert_eq!(
            Disclosure::decode(&encode_payload("zds", &payload)),
            Err(FormatError::LengthMismatch { typecode: 0x10 })
        );
    }

    #[test]
    fn rejects_signer_item_with_wrong_body_length() {
        let d = Disclosure::signed(
            NetworkType::Main,
            TxId::from_bytes(TXID),
            vec![],
            None,
            vec![spend_signer(0, None)],
        )
        .unwrap();
        let mut payload = d.payload(SignatureBytes::Include);
        // The body length is a 3-byte CompactSize after the 1-byte typecode. Drop the
        // last signature byte and lower the length by one.
        let len = u16::from_le_bytes([payload[35], payload[36]]) - 1;
        payload[35..37].copy_from_slice(&len.to_le_bytes());
        payload.pop();
        assert_eq!(
            Disclosure::decode(&encode_payload("zds", &payload)),
            Err(FormatError::LengthMismatch { typecode: 0xe0 })
        );
    }

    #[test]
    fn signing_digest_covers_the_body_and_not_the_signatures() {
        assert_eq!(sample().signing_digest(), None);

        let d = signed_sample();
        let digest = d.signing_digest().unwrap();

        let mut resigned = d.clone();
        resigned.signers_mut()[0].sig = [0x99; 64];
        assert_eq!(resigned.signing_digest(), Some(digest));

        let parts = |network, items, text| {
            Disclosure::signed(
                network,
                TxId::from_bytes(TXID),
                items,
                Some(message(text)),
                d.signers().to_vec(),
            )
            .unwrap()
            .signing_digest()
            .unwrap()
        };
        let items = vec![item(Kind::Sapling, 1)];
        assert_eq!(parts(NetworkType::Main, items.clone(), "invoice 7"), digest);
        assert_ne!(parts(NetworkType::Test, items.clone(), "invoice 7"), digest);
        assert_ne!(parts(NetworkType::Main, items, "invoice 8"), digest);
        assert_ne!(parts(NetworkType::Main, vec![], "invoice 7"), digest);
    }
}
