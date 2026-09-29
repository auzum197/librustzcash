//! The `zdisc` string encoding of a [`Disclosure`] and its canonical form.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Cursor, Read};

use bech32::{Bech32m, Checksum, Hrp, primitives::decode::CheckedHrpstring};
use zcash_encoding::CompactSize;
use zcash_protocol::{TxId, consensus::NetworkType};

/// The payload version this crate reads and writes.
pub const VERSION: u8 = 0x01;

/// The largest number of Items, known and unknown, in one Disclosure.
pub const MAX_ITEMS: usize = 64;

/// The largest Item body, in bytes.
pub const MAX_BODY_LEN: usize = 255;

/// Typecodes in this range must be understood. A decoder rejects a Disclosure that carries
/// one it does not know.
pub const MUST_UNDERSTAND: core::ops::RangeInclusive<u64> = 0xE0..=0xFF;

const KEY_LEN: usize = 32;

/// Bech32m with the 90-character limit lifted, as ZIP 316 does for Unified Addresses.
enum Bech32mDisclosure {}

impl Checksum for Bech32mDisclosure {
    type MidstateRepr = <Bech32m as Checksum>::MidstateRepr;
    const CODE_LENGTH: usize = 4194368;
    const CHECKSUM_LENGTH: usize = Bech32m::CHECKSUM_LENGTH;
    const GENERATOR_SH: [u32; 5] = Bech32m::GENERATOR_SH;
    const TARGET_RESIDUE: u32 = Bech32m::TARGET_RESIDUE;
}

/// The human-readable part for `network`.
pub fn hrp(network: NetworkType) -> &'static str {
    match network {
        NetworkType::Main => "zdisc",
        NetworkType::Test => "zdisctest",
        NetworkType::Regtest => "zdiscregtest",
    }
}

fn network_for_hrp(hrp: &str) -> Option<NetworkType> {
    match hrp {
        "zdisc" => Some(NetworkType::Main),
        "zdisctest" => Some(NetworkType::Test),
        "zdiscregtest" => Some(NetworkType::Regtest),
        _ => None,
    }
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

/// The disclosure of one output.
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

/// The disclosure of a set of shielded outputs of one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    network: NetworkType,
    txid: TxId,
    items: Vec<Item>,
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
    /// Items are not strictly increasing by `(typecode, index)`.
    NotSorted,
    /// Two Items point at the same output.
    DuplicateOutput {
        /// The bundle.
        pool: Pool,
        /// The index in the bundle.
        index: u32,
    },
    /// The Disclosure has no Item with a known typecode.
    NoKnownItems,
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
            FormatError::NotSorted => write!(f, "items are not sorted by (typecode, index)"),
            FormatError::DuplicateOutput { pool, index } => {
                write!(f, "output {index} of the {pool:?} bundle appears twice")
            }
            FormatError::NoKnownItems => write!(f, "no item with a known typecode"),
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

impl Disclosure {
    /// Builds a Disclosure from known Items. The Items are sorted into canonical order.
    pub fn new(
        network: NetworkType,
        txid: TxId,
        mut items: Vec<Item>,
    ) -> Result<Self, FormatError> {
        if items.is_empty() {
            return Err(FormatError::NoKnownItems);
        }
        if items.len() > MAX_ITEMS {
            return Err(FormatError::TooManyItems);
        }
        items.sort_by_key(|item| (item.kind.typecode(), item.index));
        let mut outputs = BTreeSet::new();
        for item in &items {
            if !outputs.insert((item.kind.pool(), item.index)) {
                return Err(FormatError::DuplicateOutput {
                    pool: item.kind.pool(),
                    index: item.index,
                });
            }
        }
        Ok(Disclosure {
            network,
            txid,
            items,
            unknown: vec![],
        })
    }

    /// The network the HRP binds this Disclosure to.
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// The transaction this Disclosure covers.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// The Items with known typecodes, in canonical order.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The Items with unknown typecodes, in the order they were decoded.
    pub fn unknown_items(&self) -> &[UnknownItem] {
        &self.unknown
    }

    /// Encodes this Disclosure as a lowercase `zdisc` string.
    pub fn encode(&self) -> String {
        let mut entries: Vec<(u64, Option<u32>, Vec<u8>)> = self
            .items
            .iter()
            .map(|item| {
                (
                    u64::from(item.kind.typecode()),
                    Some(item.index),
                    item.body(),
                )
            })
            .chain(
                self.unknown
                    .iter()
                    .map(|u| (u.typecode, None, u.body.clone())),
            )
            .collect();
        entries.sort_by_key(|(typecode, index, _)| (*typecode, *index));

        let mut payload = vec![VERSION];
        payload.extend_from_slice(self.txid.as_ref());
        for (typecode, _, body) in entries {
            CompactSize::write(&mut payload, typecode as usize)
                .expect("writes to a Vec do not fail");
            CompactSize::write(&mut payload, body.len()).expect("writes to a Vec do not fail");
            payload.extend_from_slice(&body);
        }
        bech32::encode::<Bech32mDisclosure>(Hrp::parse_unchecked(hrp(self.network)), &payload)
            .expect("MAX_ITEMS and MAX_BODY_LEN bound the length below CODE_LENGTH")
    }

    /// Decodes a `zdisc` string and enforces the canonical form.
    pub fn decode(s: &str) -> Result<Self, FormatError> {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(FormatError::Uppercase);
        }
        let parsed = CheckedHrpstring::new::<Bech32mDisclosure>(s)
            .map_err(|_| FormatError::InvalidBech32m)?;
        let network = network_for_hrp(parsed.hrp().as_str())
            .ok_or_else(|| FormatError::UnknownHrp(parsed.hrp().to_string()))?;
        parsed
            .validate_segwit_padding()
            .map_err(|_| FormatError::InvalidPadding)?;
        let payload: Vec<u8> = parsed.byte_iter().collect();
        Self::parse_payload(network, &payload)
    }

    fn parse_payload(network: NetworkType, payload: &[u8]) -> Result<Self, FormatError> {
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
        let mut unknown = vec![];
        let mut outputs = BTreeSet::new();
        let mut last: Option<(u64, Option<u32>)> = None;
        while (reader.position() as usize) < payload.len() {
            if items.len() + unknown.len() == MAX_ITEMS {
                return Err(FormatError::TooManyItems);
            }
            let typecode = read_compact(&mut reader)?;
            let len = read_compact(&mut reader)?;
            if len > MAX_BODY_LEN as u64 {
                return Err(FormatError::BodyTooLong);
            }
            let mut body = vec![0; len as usize];
            reader
                .read_exact(&mut body)
                .map_err(|_| FormatError::Truncated)?;

            let index = match Kind::from_typecode(typecode) {
                Some(kind) => {
                    let item = Item::parse(kind, &body)?;
                    if !outputs.insert((kind.pool(), item.index)) {
                        return Err(FormatError::DuplicateOutput {
                            pool: kind.pool(),
                            index: item.index,
                        });
                    }
                    let index = item.index;
                    items.push(item);
                    Some(index)
                }
                None if MUST_UNDERSTAND.contains(&typecode) => {
                    return Err(FormatError::UnknownMustUnderstand(typecode));
                }
                None => {
                    unknown.push(UnknownItem { typecode, body });
                    None
                }
            };

            if let Some((last_typecode, last_index)) = last {
                let ordered = match (last_index, index) {
                    (Some(a), Some(b)) if last_typecode == typecode => a < b,
                    _ => last_typecode <= typecode,
                };
                if !ordered {
                    return Err(FormatError::NotSorted);
                }
            }
            last = Some((typecode, index));
        }

        if items.is_empty() {
            return Err(FormatError::NoKnownItems);
        }
        Ok(Disclosure {
            network,
            txid: TxId::from_bytes(txid),
            items,
            unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            TxId::from_bytes([7; 32]),
            vec![
                item(Kind::Orchard, 3),
                item(Kind::Sapling, 1),
                item(Kind::Orchard, 0),
            ],
        )
        .unwrap()
    }

    fn with_payload(f: impl FnOnce(&mut Vec<u8>)) -> String {
        let s = sample().encode();
        let parsed = CheckedHrpstring::new::<Bech32mDisclosure>(&s).unwrap();
        let mut payload: Vec<u8> = parsed.byte_iter().collect();
        f(&mut payload);
        bech32::encode::<Bech32mDisclosure>(Hrp::parse_unchecked("zdisc"), &payload).unwrap()
    }

    #[test]
    fn round_trip() {
        let d = sample();
        let s = d.encode();
        assert!(s.starts_with("zdisc1"));
        assert_eq!(Disclosure::decode(&s), Ok(d.clone()));
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
        assert!(s.starts_with("zdisctest1"));
        assert_eq!(Disclosure::decode(&s).unwrap().network(), NetworkType::Test);
    }

    #[test]
    fn rejects_uppercase() {
        let s = sample().encode().to_uppercase();
        assert_eq!(Disclosure::decode(&s), Err(FormatError::Uppercase));
    }

    #[test]
    fn rejects_unknown_hrp() {
        let s =
            bech32::encode::<Bech32mDisclosure>(Hrp::parse_unchecked("zdp"), &[1, 2, 3]).unwrap();
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::UnknownHrp("zdp".into()))
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
        let s = with_payload(|p| p.extend_from_slice(&[0x10, 0x02, 0xaa, 0xbb]));
        let d = Disclosure::decode(&s).unwrap();
        assert_eq!(
            d.unknown_items(),
            &[UnknownItem {
                typecode: 0x10,
                body: vec![0xaa, 0xbb]
            }]
        );
        assert_eq!(d.encode(), s);
    }

    #[test]
    fn rejects_unknown_must_understand_typecode() {
        let s = with_payload(|p| p.extend_from_slice(&[0xe0, 0x00]));
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::UnknownMustUnderstand(0xe0))
        );
    }

    #[test]
    fn rejects_disclosure_without_known_items() {
        let mut payload = vec![VERSION];
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&[0x10, 0x00]);
        let s =
            bech32::encode::<Bech32mDisclosure>(Hrp::parse_unchecked("zdisc"), &payload).unwrap();
        assert_eq!(Disclosure::decode(&s), Err(FormatError::NoKnownItems));
    }

    #[test]
    fn rejects_unknown_version() {
        let s = with_payload(|p| p[0] = 0x02);
        assert_eq!(
            Disclosure::decode(&s),
            Err(FormatError::UnknownVersion(0x02))
        );
    }
}
