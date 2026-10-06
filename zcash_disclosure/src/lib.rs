//! Zcash payment disclosures.
//!
//! A Disclosure is a Bech32m string that lets any holder decrypt and check a chosen set of
//! Sapling, Orchard or Ironwood outputs of one transaction. Each Output Item carries the
//! receiver's transmission key and one per-output secret: `rseed` for notes that follow
//! ZIP 212 or ZIP 2005, and `esk` or `K_enc` for Sapling notes with lead byte `0x01`.
//!
//! A Disclosure has one of two classes, which its human-readable part states:
//!
//! - [`Class::Unsigned`]: Output Items only. A watch-only wallet produces them from its
//!   full viewing keys. It shows what was paid and to which address, and no more.
//! - [`Class::Signed`]: Output Items, one or more Signer Items and an optional message. A
//!   Signer Item needs a spending key. It shows that a payer, or the owner of a receiver
//!   address, made the Disclosure. Signer Items exist for Sapling only.
//!
//! The crate has these parts:
//!
//! - [`Disclosure`] encodes and decodes the string and enforces its canonical form.
//! - [`discover`] lists the outputs of a transaction that a set of viewing keys can
//!   disclose.
//! - [`prepare_sapling_spend`], [`prepare_sapling_address_owner`] and
//!   [`PendingDisclosure`] produce a signed Disclosure.
//! - [`verify()`] checks a Disclosure against the transaction it covers.
//! - [`set`] reads and writes Disclosure sets, one Disclosure per line.
//!
//! A verified Output Item binds the note fields and the memo to the output (properties P1
//! and P2 of the specification). Items of every kind except
//! [`Kind::SaplingLegacyReceiver`] also show that the receiver can decrypt the output
//! (P6). A Disclosure carries no evidence of block inclusion, transaction validity or
//! spend status. An unsigned Disclosure carries no evidence of authorship.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

mod encoding;
mod produce;
pub mod set;
mod sign;
mod verify;
mod zip304;

pub use encoding::{
    AddressOwnerSigner, AddressProof, Class, Disclosure, FormatError, Item, Kind, MAX_BODY_LEN,
    MAX_ITEMS, MAX_MESSAGE_LEN, MUST_UNDERSTAND, Message, Pool, Signer, SignerBody, SignerKind,
    SpendSigner, UnknownItem, VERSION, hrp,
};
pub use produce::{Disclosable, Role, ViewingKeys, discover, discover_action, discover_sapling};
pub use sign::{
    PendingDisclosure, PreparedSigner, SenderAddress, SignError, SpentNote, prepare_ironwood_spend,
    prepare_orchard_address_owner, prepare_orchard_spend, prepare_sapling_address_owner,
    prepare_sapling_spend, prepare_transparent_input,
};
pub use verify::{
    AddressOwner, DisclosedNote, ItemError, Report, SignedReport, SignerError, SignerStatement,
    SpendAuthority, VerifyError, verify, verify_action, verify_address_owner_signer,
    verify_sapling_output, verify_spend_signer,
};

#[cfg(test)]
mod tests;
