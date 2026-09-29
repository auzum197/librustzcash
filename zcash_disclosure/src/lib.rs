//! Shielded note disclosures.
//!
//! A Disclosure is a `zdisc` string that lets any holder decrypt and check a chosen set of
//! Sapling, Orchard or Ironwood outputs of one transaction. Each Item carries the receiver's
//! transmission key and one per-output secret: `rseed` for notes that follow ZIP 212 or
//! ZIP 2005, and `esk` or `K_enc` for Sapling notes with lead byte `0x01`. A watch-only
//! wallet produces Items from its full viewing keys. No spending key is involved, and no
//! Item signs anything.
//!
//! - [`Disclosure`] encodes and decodes the string and enforces its canonical form.
//! - [`discover`] lists the outputs of a transaction that a set of viewing keys can
//!   disclose.
//! - [`verify`] checks a Disclosure against the transaction it covers.
//! - [`set`] reads and writes Disclosure sets, one Disclosure per line.
//!
//! A verified Item binds the note fields and the memo to the output (properties P1 and P2
//! of the specification). Items of every kind except [`Kind::SaplingLegacyReceiver`] also
//! show that the receiver can decrypt the output (P6). A Disclosure carries no evidence of
//! block inclusion, transaction validity, spend status or authorship.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

mod encoding;
mod produce;
pub mod set;
mod verify;

pub use encoding::{
    Disclosure, FormatError, Item, Kind, MAX_BODY_LEN, MAX_ITEMS, MUST_UNDERSTAND, Pool,
    UnknownItem, VERSION, hrp,
};
pub use produce::{Disclosable, Role, ViewingKeys, discover, discover_action, discover_sapling};
pub use verify::{
    DisclosedNote, ItemError, Report, VerifyError, verify, verify_action, verify_sapling_output,
};

#[cfg(test)]
mod tests;
