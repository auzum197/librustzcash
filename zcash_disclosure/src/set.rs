//! Disclosure sets: one Disclosure per line, for several transactions.

use std::collections::BTreeSet;
use std::fmt;

use crate::encoding::{Disclosure, FormatError};

/// A violation of the Disclosure set format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetError {
    /// The set has no lines.
    Empty,
    /// The last line does not end with LF.
    MissingFinalNewline,
    /// A line is not a canonical Disclosure. Lines count from 1.
    Line {
        /// The line number.
        line: usize,
        /// The encoding error.
        error: FormatError,
    },
    /// A line is for a different network from the first line. Lines of the two classes
    /// can share a set.
    MixedNetworks {
        /// The line number.
        line: usize,
    },
    /// A txid appears on an earlier line.
    DuplicateTxid {
        /// The line number.
        line: usize,
    },
}

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetError::Empty => write!(f, "the set has no disclosures"),
            SetError::MissingFinalNewline => write!(f, "the last line does not end with LF"),
            SetError::Line { line, error } => write!(f, "line {line}: {error}"),
            SetError::MixedNetworks { line } => {
                write!(f, "line {line} is for another network")
            }
            SetError::DuplicateTxid { line } => {
                write!(f, "line {line} repeats the txid of an earlier line")
            }
        }
    }
}

impl std::error::Error for SetError {}

/// Parses the text of a `.zdisc` file.
pub fn parse(text: &str) -> Result<Vec<Disclosure>, SetError> {
    if text.is_empty() {
        return Err(SetError::Empty);
    }
    let body = text
        .strip_suffix('\n')
        .ok_or(SetError::MissingFinalNewline)?;

    let mut txids = BTreeSet::new();
    let mut set: Vec<Disclosure> = vec![];
    for (i, s) in body.split('\n').enumerate() {
        let line = i + 1;
        let disclosure = Disclosure::decode(s).map_err(|error| SetError::Line { line, error })?;
        if set
            .first()
            .is_some_and(|first| first.network() != disclosure.network())
        {
            return Err(SetError::MixedNetworks { line });
        }
        if !txids.insert(*disclosure.txid().as_ref()) {
            return Err(SetError::DuplicateTxid { line });
        }
        set.push(disclosure);
    }
    Ok(set)
}

/// Writes `set` as the text of a `.zdisc` file.
pub fn format(set: &[Disclosure]) -> Result<String, SetError> {
    let first = set.first().ok_or(SetError::Empty)?;
    let mut txids = BTreeSet::new();
    let mut text = String::new();
    for (i, disclosure) in set.iter().enumerate() {
        let line = i + 1;
        if disclosure.network() != first.network() {
            return Err(SetError::MixedNetworks { line });
        }
        if !txids.insert(*disclosure.txid().as_ref()) {
            return Err(SetError::DuplicateTxid { line });
        }
        text.push_str(&disclosure.encode());
        text.push('\n');
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use zcash_protocol::{TxId, consensus::NetworkType};

    use super::*;
    use crate::encoding::{Item, Kind};

    fn disclosure(network: NetworkType, txid: u8) -> Disclosure {
        Disclosure::new(
            network,
            TxId::from_bytes([txid; 32]),
            vec![Item {
                kind: Kind::Orchard,
                index: 0,
                pk_d: [1; 32],
                secret: [2; 32],
            }],
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let set = vec![
            disclosure(NetworkType::Main, 1),
            disclosure(NetworkType::Main, 2),
        ];
        let text = format(&set).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(parse(&text), Ok(set));
    }

    #[test]
    fn rejects_duplicate_txid_and_mixed_networks() {
        let same = [
            disclosure(NetworkType::Main, 1),
            disclosure(NetworkType::Main, 1),
        ];
        assert_eq!(format(&same), Err(SetError::DuplicateTxid { line: 2 }));

        let mixed = format!(
            "{}\n{}\n",
            disclosure(NetworkType::Main, 1).encode(),
            disclosure(NetworkType::Test, 2).encode()
        );
        assert_eq!(parse(&mixed), Err(SetError::MixedNetworks { line: 2 }));
    }

    #[test]
    fn requires_final_newline() {
        let text = disclosure(NetworkType::Main, 1).encode();
        assert_eq!(parse(&text), Err(SetError::MissingFinalNewline));
        assert_eq!(parse(""), Err(SetError::Empty));
    }
}
