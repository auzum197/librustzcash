//! The statement of a [ZIP 304] address proof: a Sapling spend proof for a fixed note at
//! the address, in a tree that holds only that note.
//!
//! [ZIP 304]: https://zips.z.cash/zip-0304

use ff::Field;
use incrementalmerkletree::{Hashable, Level, Position};
use sapling::{
    MerklePath, NOTE_COMMITMENT_TREE_DEPTH, Node, Note, PaymentAddress, Rseed,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};

/// The value of the ZIP 304 note, in zatoshis. The Spend circuit disables some
/// constraints for a zero value, so ZIP 304 uses 1 to bind the address to the proof.
const NOTE_VALUE: u64 = 1;

/// The position of the ZIP 304 note in its tree.
pub(crate) const NOTE_POSITION: u64 = 0;

/// The public and auxiliary inputs of an address proof that the address fixes.
pub(crate) struct AddressStatement {
    note: Note,
    merkle_path: MerklePath,
    anchor: bls12_381::Scalar,
}

impl AddressStatement {
    pub(crate) fn new(address: PaymentAddress) -> Self {
        // ZIP 304 sets rcm = 0. The note needs no hiding.
        let note = address.create_note(Self::value(), Rseed::BeforeZip212(jubjub::Fr::ZERO));
        let siblings = (0..NOTE_COMMITMENT_TREE_DEPTH)
            .map(|level| Node::empty_root(Level::from(level)))
            .collect();
        let merkle_path = MerklePath::from_parts(siblings, Position::from(NOTE_POSITION))
            .expect("one sibling per tree level");
        let anchor = merkle_path.root(Node::from_cmu(&note.cmu())).into();
        AddressStatement {
            note,
            merkle_path,
            anchor,
        }
    }

    pub(crate) fn note(&self) -> &Note {
        &self.note
    }

    pub(crate) fn merkle_path(&self) -> MerklePath {
        self.merkle_path.clone()
    }

    /// The root of the tree that holds only the ZIP 304 note.
    pub(crate) fn anchor(&self) -> bls12_381::Scalar {
        self.anchor
    }

    pub(crate) fn value() -> NoteValue {
        NoteValue::from_raw(NOTE_VALUE)
    }

    /// ZIP 304 sets rcv = 0. The value is public.
    pub(crate) fn rcv() -> ValueCommitTrapdoor {
        ValueCommitTrapdoor::from_bytes(jubjub::Fr::ZERO.to_bytes())
            .expect("zero is a canonical scalar")
    }

    /// The value commitment of every address proof.
    pub(crate) fn cv() -> ValueCommitment {
        ValueCommitment::derive(Self::value(), Self::rcv())
    }
}
