//! Production of Signer Items and of signed Disclosures.

use std::fmt;

use ff::Field;
use rand_core::{CryptoRng, Rng};
use redjubjub::{Signature, SpendAuth, VerificationKey};
use sapling::{
    MerklePath, Node, Note, PaymentAddress, ProofGenerationKey,
    bundle::{Authorization, SpendDescription},
    keys::SpendAuthorizingKey,
    prover::SpendProver,
    value::{ValueCommitTrapdoor, ValueCommitment},
};
use zcash_protocol::{TxId, consensus::NetworkType};

use crate::{
    encoding::{
        AddressOwnerSigner, AddressProof, Disclosure, FormatError, Item, Message, Signer,
        SignerBody, SignerKind, SpendSigner,
    },
    zip304::{AddressStatement, NOTE_POSITION},
};

/// The signature bytes of a Signer Item that has no signature yet. The digest does not
/// cover them, and [`PendingDisclosure::finish`] refuses to emit them.
const SIGNATURE_PLACEHOLDER: [u8; 64] = [0; 64];

/// Why a Signer Item or a signed Disclosure could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The proof generation key does not control the address of the note.
    KeyMismatch,
    /// The Merkle path does not lead to the anchor of the spend.
    AnchorMismatch,
    /// The note at this position does not have the nullifier of the spend.
    NullifierMismatch,
    /// The Disclosure has no Signer Item with these fields.
    UnknownSigner,
    /// The signature is not valid for the Signer Item over the digest of the Disclosure.
    InvalidSignature,
    /// A Signer Item has no signature.
    MissingSignature(SignerKind),
    /// The parts do not make a canonical signed Disclosure.
    Format(FormatError),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::KeyMismatch => write!(f, "the key does not control the address"),
            SignError::AnchorMismatch => {
                write!(
                    f,
                    "the Merkle path does not lead to the anchor of the spend"
                )
            }
            SignError::NullifierMismatch => {
                write!(f, "the note does not have the nullifier of the spend")
            }
            SignError::UnknownSigner => write!(f, "the disclosure has no such signer item"),
            SignError::InvalidSignature => write!(f, "the signature is not valid"),
            SignError::MissingSignature(kind) => {
                write!(
                    f,
                    "a signer item of typecode {:#04x} has no signature",
                    kind.typecode()
                )
            }
            SignError::Format(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<FormatError> for SignError {
    fn from(error: FormatError) -> Self {
        SignError::Format(error)
    }
}

/// Whether a spend signer proves its payment address to the Verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderAddress {
    /// The Signer Item has typecode `0xE0` and names no address.
    Hidden,
    /// The Signer Item has typecode `0xE1` and proves the address of the spent note.
    Revealed,
}

/// The note that a Sapling spend consumed, with its path to the anchor of that spend.
#[derive(Clone, Debug)]
pub struct SpentNote {
    note: Note,
    merkle_path: MerklePath,
}

impl SpentNote {
    /// Pairs a note with its Merkle path.
    pub fn new(note: Note, merkle_path: MerklePath) -> Self {
        SpentNote { note, merkle_path }
    }
}

/// The fields of a Signer Item before its signature, with the randomizer that the
/// signature needs.
///
/// The Signer shares [`PreparedSigner::body`] with the other Signers of the Disclosure and
/// keeps the value itself until it signs.
pub struct PreparedSigner {
    pub(crate) body: SignerBody,
    pub(crate) alpha: jubjub::Scalar,
}

impl PreparedSigner {
    /// The fields that go into the Disclosure.
    pub fn body(&self) -> &SignerBody {
        &self.body
    }
}

impl fmt::Debug for PreparedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSigner")
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// Prepares a Signer Item that proves spend authority over Sapling spend `index`.
///
/// `spend` is the spend description at `index` in the transaction. `spent` is the note
/// it consumed and the Merkle path of that note to the anchor of the spend.
///
/// # Errors
///
/// - [`SignError::KeyMismatch`] when `proof_generation_key` does not control the address
///   of the note.
/// - [`SignError::AnchorMismatch`] or [`SignError::NullifierMismatch`] when `spent` is
///   not the note that `spend` consumed.
pub fn prepare_sapling_spend<SP, A, R>(
    prover: &SP,
    mut rng: R,
    proof_generation_key: &ProofGenerationKey,
    index: u32,
    spend: &SpendDescription<A>,
    spent: SpentNote,
    sender_address: SenderAddress,
) -> Result<PreparedSigner, SignError>
where
    SP: SpendProver,
    A: Authorization,
    R: Rng + CryptoRng,
{
    let SpentNote { note, merkle_path } = spent;
    let address = note.recipient();
    let viewing_key = proof_generation_key.to_viewing_key();
    if viewing_key.to_payment_address(*address.diversifier()) != Some(address) {
        return Err(SignError::KeyMismatch);
    }
    let anchor = bls12_381::Scalar::from(merkle_path.root(Node::from_cmu(&note.cmu())));
    if &anchor != spend.anchor() {
        return Err(SignError::AnchorMismatch);
    }
    if &note.nf(viewing_key.nk(), merkle_path.position().into()) != spend.nullifier() {
        return Err(SignError::NullifierMismatch);
    }

    let alpha = jubjub::Scalar::random(&mut rng);
    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let cv = ValueCommitment::derive(note.value(), rcv.clone());
    let circuit = SP::prepare_circuit(
        proof_generation_key.clone(),
        *address.diversifier(),
        *note.rseed(),
        note.value(),
        alpha,
        rcv,
        anchor,
        merkle_path,
    )
    .ok_or(SignError::KeyMismatch)?;
    let zkproof = SP::encode_proof(prover.create_proof(circuit, &mut rng));

    let address = match sender_address {
        SenderAddress::Hidden => None,
        SenderAddress::Revealed => Some(prove_address(
            prover,
            &mut rng,
            proof_generation_key,
            address,
            alpha,
        )?),
    };

    Ok(PreparedSigner {
        body: SignerBody::SaplingSpend(SpendSigner {
            index,
            cv: cv.to_bytes(),
            rk: proof_generation_key.ak().randomize(&alpha).into(),
            zkproof,
            address,
        }),
        alpha,
    })
}

/// Prepares a Signer Item that proves control of `address`, the receiver address of a
/// Sapling output that the Disclosure lists.
///
/// # Errors
///
/// [`SignError::KeyMismatch`] when `proof_generation_key` does not control `address`.
pub fn prepare_sapling_address_owner<SP, R>(
    prover: &SP,
    mut rng: R,
    proof_generation_key: &ProofGenerationKey,
    address: PaymentAddress,
) -> Result<PreparedSigner, SignError>
where
    SP: SpendProver,
    R: Rng + CryptoRng,
{
    let alpha = jubjub::Scalar::random(&mut rng);
    let address = prove_address(prover, &mut rng, proof_generation_key, address, alpha)?;
    Ok(PreparedSigner {
        body: SignerBody::SaplingAddressOwner(AddressOwnerSigner {
            address,
            rk: proof_generation_key.ak().randomize(&alpha).into(),
        }),
        alpha,
    })
}

/// Makes the proof of the ZIP 304 signature algorithm for `address` under the randomizer
/// `alpha`.
fn prove_address<SP: SpendProver, R: Rng + CryptoRng>(
    prover: &SP,
    rng: &mut R,
    proof_generation_key: &ProofGenerationKey,
    address: PaymentAddress,
    alpha: jubjub::Scalar,
) -> Result<AddressProof, SignError> {
    let viewing_key = proof_generation_key.to_viewing_key();
    if viewing_key.to_payment_address(*address.diversifier()) != Some(address) {
        return Err(SignError::KeyMismatch);
    }
    let statement = AddressStatement::new(address);
    let circuit = SP::prepare_circuit(
        proof_generation_key.clone(),
        *address.diversifier(),
        *statement.note().rseed(),
        AddressStatement::value(),
        alpha,
        AddressStatement::rcv(),
        statement.anchor(),
        statement.merkle_path(),
    )
    .ok_or(SignError::KeyMismatch)?;

    let address_bytes = address.to_bytes();
    let (diversifier, pk_d) = address_bytes.split_at(address.diversifier().0.len());
    Ok(AddressProof {
        diversifier: diversifier.try_into().expect("11-byte diversifier"),
        pk_d: pk_d.try_into().expect("32-byte pk_d"),
        nf_addr: statement.note().nf(viewing_key.nk(), NOTE_POSITION).0,
        zkproof: SP::encode_proof(prover.create_proof(circuit, rng)),
    })
}

/// Prepares a Signer Item that proves spend authority over an Orchard action.
///
/// # Panics
///
/// Always. No specification defines a spend signer for Orchard. Its typecode is in the
/// reserved range `0xE3` to `0xEF`.
pub fn prepare_orchard_spend(_index: u32) -> PreparedSigner {
    todo!("spend signer Items for Orchard actions are reserved and not specified")
}

/// Prepares a Signer Item that proves spend authority over an Ironwood action.
///
/// # Panics
///
/// Always. No specification defines a spend signer for Ironwood. Its typecode is in the
/// reserved range `0xE3` to `0xEF`.
pub fn prepare_ironwood_spend(_index: u32) -> PreparedSigner {
    todo!("spend signer Items for Ironwood actions are reserved and not specified")
}

/// Prepares a Signer Item that proves spend authority over a transparent input.
///
/// # Panics
///
/// Always. ZIP 311 leaves BIP 322 signatures for transparent inputs open. The typecode
/// is in the reserved range `0xE3` to `0xEF`.
pub fn prepare_transparent_input(_index: u32) -> PreparedSigner {
    todo!("signer Items for transparent inputs are reserved and not specified")
}

/// Prepares a Signer Item that proves control of the receiver address of an Orchard or
/// Ironwood output that the Disclosure lists. The two pools share one address space.
///
/// # Panics
///
/// Always. ZIP 304 covers Sapling addresses only, and no specification defines an
/// address proof for Orchard addresses. The typecode is in the reserved range `0xE3` to
/// `0xEF`.
pub fn prepare_orchard_address_owner(_address: orchard::Address) -> PreparedSigner {
    todo!("address owner signer Items for Orchard and Ironwood are reserved and not specified")
}

/// A signed Disclosure whose Signer Items are all in place and not all signed.
///
/// Every Signer prepares its Item first. The digest is fixed when this value is built,
/// and then each Signer signs it.
#[derive(Clone, Debug)]
pub struct PendingDisclosure {
    disclosure: Disclosure,
    digest: [u8; 32],
    signed: Vec<bool>,
}

impl PendingDisclosure {
    /// Fixes the body of a signed Disclosure: its Output Items, its message and the
    /// fields of its Signer Items.
    ///
    /// # Errors
    ///
    /// A [`FormatError`] when the parts break the canonical form, for example when
    /// `signers` is empty or two Signer Items cover the same spend.
    pub fn new(
        network: NetworkType,
        txid: TxId,
        items: Vec<Item>,
        message: Option<Message>,
        signers: Vec<SignerBody>,
    ) -> Result<Self, FormatError> {
        let signers = signers
            .into_iter()
            .map(|body| Signer {
                body,
                sig: SIGNATURE_PLACEHOLDER,
            })
            .collect();
        let disclosure = Disclosure::signed(network, txid, items, message, signers)?;
        let digest = disclosure
            .signing_digest()
            .expect("a signed Disclosure has a digest");
        let signed = vec![false; disclosure.signers().len()];
        Ok(PendingDisclosure {
            disclosure,
            digest,
            signed,
        })
    }

    /// The digest that every Signer signs.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The fields of the Signer Items, in canonical order.
    pub fn signer_bodies(&self) -> impl Iterator<Item = &SignerBody> {
        self.disclosure.signers().iter().map(Signer::body)
    }

    /// Signs the Item of `prepared` with the spend authorizing key `ask`.
    ///
    /// # Errors
    ///
    /// - [`SignError::UnknownSigner`] when the Disclosure does not hold the Item.
    /// - [`SignError::InvalidSignature`] when `ask` is not the key of the Item.
    pub fn sign<R: Rng + CryptoRng>(
        &mut self,
        rng: R,
        prepared: &PreparedSigner,
        ask: &SpendAuthorizingKey,
    ) -> Result<(), SignError> {
        let sig = ask.randomize(&prepared.alpha).sign(rng, &self.digest);
        self.attach_signature(&prepared.body, sig)
    }

    /// Adds a signature that a Signer made over [`PendingDisclosure::digest`] for the
    /// Signer Item with the fields `body`.
    ///
    /// # Errors
    ///
    /// - [`SignError::UnknownSigner`] when the Disclosure does not hold the Item.
    /// - [`SignError::InvalidSignature`] when the signature is not valid for the Item.
    pub fn attach_signature(
        &mut self,
        body: &SignerBody,
        sig: Signature<SpendAuth>,
    ) -> Result<(), SignError> {
        let position = self
            .signer_bodies()
            .position(|candidate| candidate == body)
            .ok_or(SignError::UnknownSigner)?;
        VerificationKey::<SpendAuth>::try_from(*body.rk())
            .and_then(|rk| rk.verify(&self.digest, &sig))
            .map_err(|_| SignError::InvalidSignature)?;
        self.disclosure.signers_mut()[position].sig = sig.into();
        self.signed[position] = true;
        Ok(())
    }

    /// Returns the signed Disclosure.
    ///
    /// # Errors
    ///
    /// [`SignError::MissingSignature`] when a Signer Item has no signature.
    pub fn finish(self) -> Result<Disclosure, SignError> {
        match self.signed.iter().position(|signed| !signed) {
            Some(position) => Err(SignError::MissingSignature(
                self.disclosure.signers()[position].body().kind(),
            )),
            None => Ok(self.disclosure),
        }
    }
}
