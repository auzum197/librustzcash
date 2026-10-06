//! Round trips through real bundles: `discover` produces an Item from viewing keys, and the
//! Verifier opens the same output with it. The signed tests add Signer Items with real
//! Sapling spend proofs and check them against a transaction.

use std::sync::LazyLock;

use incrementalmerkletree::{Hashable, Level, Position};
use orchard::{
    bundle::{BundleVersion, Flags},
    keys::{FullViewingKey, Scope, SpendingKey},
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sapling::{
    MerklePath, NOTE_COMMITMENT_TREE_DEPTH, Node, PaymentAddress, Rseed,
    circuit::PreparedSpendVerifyingKey,
    note_encryption::Zip212Enforcement,
    prover::mock::{MockOutputProver, MockSpendProver},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use zcash_primitives::transaction::{Transaction, TransactionData, TxVersion};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, TestNetwork},
    value::ZatBalance,
};

use crate::{
    Class, Disclosure, FormatError, Item, ItemError, Kind, Message, PendingDisclosure,
    PreparedSigner, Role, SenderAddress, SignError, SignerBody, SignerError, SignerKind,
    SignerStatement, SpentNote, VerifyError, discover_action, discover_sapling,
    prepare_ironwood_spend, prepare_orchard_address_owner, prepare_orchard_spend,
    prepare_sapling_address_owner, prepare_sapling_spend, prepare_transparent_input, verify,
    verify_action, verify_sapling_output,
};

const VALUE: u64 = 250_000_000;

/// The value of the note that the signed tests spend, in zatoshis.
const SPENT_VALUE: u64 = 300_000_000;

/// The height of the transaction in the signed tests. It is after the end of the ZIP 212
/// grace period on mainnet and on testnet.
const HEIGHT: u32 = 2_000_000;

const MEMO: &str = "Invoice #2291";

fn memo(text: &str) -> [u8; 512] {
    let mut memo = [0; 512];
    memo[..text.len()].copy_from_slice(text.as_bytes());
    memo
}

fn sapling_key(seed: u8) -> DiversifiableFullViewingKey {
    ExtendedSpendingKey::master(&[seed; 32])
        .unwrap()
        .to_diversifiable_full_viewing_key()
}

/// A Sapling bundle with one real output from `sender` to `receiver`, and the output's
/// position in it.
fn sapling_bundle(
    zip212: Zip212Enforcement,
    sender: &DiversifiableFullViewingKey,
    receiver: &DiversifiableFullViewingKey,
) -> (sapling::builder::UnauthorizedBundle<i64>, usize) {
    let mut builder = sapling::builder::Builder::new(
        zip212,
        sapling::builder::BundleType::DEFAULT,
        sapling::Anchor::empty_tree(),
    );
    builder
        .add_output(
            Some(sender.to_ovk(Scope::External)),
            receiver.default_address().1,
            NoteValue::from_raw(VALUE),
            memo(MEMO),
        )
        .unwrap();
    let (bundle, meta) = builder
        .build::<MockSpendProver, MockOutputProver, _, i64>(&[], ChaCha8Rng::seed_from_u64(1))
        .unwrap()
        .unwrap();
    (bundle, meta.output_index(0).unwrap())
}

fn orchard_key(seed: u8) -> FullViewingKey {
    FullViewingKey::from(
        &SpendingKey::from_zip32_seed(&[seed; 32], 133, zip32::AccountId::ZERO).unwrap(),
    )
}

/// An Orchard-protocol bundle for `version` with one real output from `sender` to
/// `receiver`, and the output's action index.
fn action_bundle(
    version: BundleVersion,
    sender: &FullViewingKey,
    receiver: &FullViewingKey,
) -> (orchard::builder::UnauthorizedBundle<i64>, usize) {
    let mut builder = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        Flags::ENABLED,
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            Some(sender.to_ovk(Scope::External)),
            receiver.address_at(0u32, Scope::External),
            orchard::value::NoteValue::from_raw(VALUE),
            memo("Rent, October"),
        )
        .unwrap();
    let (bundle, meta) = builder
        .build::<i64>(ChaCha8Rng::seed_from_u64(2))
        .unwrap()
        .unwrap();
    (bundle, meta.output_action_index(0).unwrap())
}

#[test]
fn sapling_receiver_and_sender_items_verify() {
    let (sender, receiver) = (sapling_key(1), sapling_key(2));
    let (bundle, index) = sapling_bundle(Zip212Enforcement::On, &sender, &receiver);
    let output = &bundle.shielded_outputs()[index];

    for (keys, role) in [(&receiver, Role::Receiver), (&sender, Role::Sender)] {
        let found = discover_sapling(keys, Zip212Enforcement::On, index as u32, output).unwrap();
        assert_eq!(found.role, role);
        assert_eq!(found.item.kind, Kind::Sapling);

        let note = verify_sapling_output(output, Zip212Enforcement::On, &found.item).unwrap();
        assert_eq!(note.value, VALUE);
        assert_eq!(note.memo, memo(MEMO));
        assert!(note.receivable());
    }
}

#[test]
fn sapling_item_rejects_altered_secret_and_pk_d() {
    let (sender, receiver) = (sapling_key(1), sapling_key(2));
    let (bundle, index) = sapling_bundle(Zip212Enforcement::On, &sender, &receiver);
    let output = &bundle.shielded_outputs()[index];
    let item = discover_sapling(&receiver, Zip212Enforcement::On, index as u32, output)
        .unwrap()
        .item;

    let mut altered = item.clone();
    altered.secret[0] ^= 1;
    assert_eq!(
        verify_sapling_output(output, Zip212Enforcement::On, &altered),
        Err(ItemError::Rejected)
    );

    let other = Item {
        pk_d: sapling_key(3).default_address().1.to_bytes()[11..]
            .try_into()
            .unwrap(),
        ..item
    };
    assert_eq!(
        verify_sapling_output(output, Zip212Enforcement::On, &other),
        Err(ItemError::Rejected)
    );
}

#[test]
fn sapling_item_rejects_identity_pk_d() {
    let (sender, receiver) = (sapling_key(1), sapling_key(2));
    let (bundle, index) = sapling_bundle(Zip212Enforcement::On, &sender, &receiver);
    let output = &bundle.shielded_outputs()[index];
    let mut identity = [0; 32];
    identity[0] = 0x01;
    let item = Item {
        kind: Kind::Sapling,
        index: index as u32,
        pk_d: identity,
        secret: [0; 32],
    };
    assert_eq!(
        verify_sapling_output(output, Zip212Enforcement::On, &item),
        Err(ItemError::InvalidPkd)
    );
}

#[test]
fn legacy_sapling_items_verify_only_before_the_grace_period_ends() {
    let (sender, receiver) = (sapling_key(1), sapling_key(2));
    let (bundle, index) = sapling_bundle(Zip212Enforcement::Off, &sender, &receiver);
    let output = &bundle.shielded_outputs()[index];

    let received =
        discover_sapling(&receiver, Zip212Enforcement::Off, index as u32, output).unwrap();
    assert_eq!(received.item.kind, Kind::SaplingLegacyReceiver);
    let note = verify_sapling_output(output, Zip212Enforcement::Off, &received.item).unwrap();
    assert_eq!(note.value, VALUE);
    assert!(!note.receivable());

    let sent = discover_sapling(&sender, Zip212Enforcement::Off, index as u32, output).unwrap();
    assert_eq!(sent.item.kind, Kind::SaplingLegacySender);
    let note = verify_sapling_output(output, Zip212Enforcement::Off, &sent.item).unwrap();
    assert_eq!(note.memo, memo(MEMO));
    assert!(note.receivable());

    for item in [&received.item, &sent.item] {
        assert_eq!(
            verify_sapling_output(output, Zip212Enforcement::GracePeriod, item).map(|n| n.value),
            Ok(VALUE)
        );
        assert_eq!(
            verify_sapling_output(output, Zip212Enforcement::On, item),
            Err(ItemError::Rejected)
        );
    }
}

#[test]
fn legacy_self_send_prefers_the_sender_item() {
    let keys = sapling_key(1);
    let (bundle, index) = sapling_bundle(Zip212Enforcement::Off, &keys, &keys);
    let output = &bundle.shielded_outputs()[index];

    let found = discover_sapling(&keys, Zip212Enforcement::Off, index as u32, output).unwrap();
    assert_eq!(found.item.kind, Kind::SaplingLegacySender);
    assert!(
        verify_sapling_output(output, Zip212Enforcement::Off, &found.item)
            .unwrap()
            .receivable()
    );
}

#[test]
fn orchard_and_ironwood_items_verify_in_their_own_pool_only() {
    let (sender, receiver) = (orchard_key(4), orchard_key(5));
    for (version, kind, other) in [
        (BundleVersion::orchard_v2(), Kind::Orchard, Kind::Ironwood),
        (BundleVersion::ironwood_v3(), Kind::Ironwood, Kind::Orchard),
    ] {
        let (bundle, index) = action_bundle(version, &sender, &receiver);
        let action = &bundle.actions()[index];

        for (keys, role) in [(&receiver, Role::Receiver), (&sender, Role::Sender)] {
            let found = discover_action(keys, kind, index as u32, action).unwrap();
            assert_eq!(found.role, role);

            let note = verify_action(action, &found.item).unwrap();
            assert_eq!(note.value, VALUE);
            assert_eq!(note.memo, memo("Rent, October"));

            let misrouted = Item {
                kind: other,
                ..found.item.clone()
            };
            assert_eq!(verify_action(action, &misrouted), Err(ItemError::Rejected));

            let mut altered = found.item.clone();
            altered.secret[5] ^= 0x80;
            assert!(verify_action(action, &altered).is_err());
        }
    }
}

#[test]
fn keys_that_cannot_open_an_output_find_nothing() {
    let (bundle, index) = sapling_bundle(Zip212Enforcement::On, &sapling_key(1), &sapling_key(2));
    let output = &bundle.shielded_outputs()[index];
    assert!(
        discover_sapling(&sapling_key(9), Zip212Enforcement::On, index as u32, output).is_none()
    );

    let (bundle, index) = action_bundle(
        BundleVersion::orchard_v2(),
        &orchard_key(4),
        &orchard_key(5),
    );
    let action = &bundle.actions()[index];
    assert!(discover_action(&orchard_key(9), Kind::Orchard, index as u32, action).is_none());
}

/// The Sapling parameters. Signer Items carry real proofs, which the mock provers of the
/// bundle builders cannot make.
static PROVER: LazyLock<LocalTxProver> = LazyLock::new(LocalTxProver::bundled);

fn spend_vk() -> PreparedSpendVerifyingKey {
    PROVER.verifying_keys().0.prepare()
}

fn rng(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

fn sapling_spending_key(seed: u8) -> ExtendedSpendingKey {
    ExtendedSpendingKey::master(&[seed; 32]).unwrap()
}

fn default_address(key: &ExtendedSpendingKey) -> PaymentAddress {
    key.to_diversifiable_full_viewing_key().default_address().1
}

/// A transaction in which `sender` spends one note and pays [`VALUE`] to `receiver`.
struct Payment {
    tx: Transaction,
    spend_index: u32,
    output_index: u32,
    spent: SpentNote,
}

impl Payment {
    /// The proofs and signatures of the transaction are placeholders. A Verifier of a
    /// Disclosure does not check them.
    fn new(sender: &ExtendedSpendingKey, receiver: PaymentAddress) -> Self {
        let dfvk = sender.to_diversifiable_full_viewing_key();
        let note = default_address(sender).create_note(
            NoteValue::from_raw(SPENT_VALUE),
            Rseed::AfterZip212([9; 32]),
        );
        // The note is the only leaf of its commitment tree.
        let merkle_path = MerklePath::from_parts(
            (0..NOTE_COMMITMENT_TREE_DEPTH)
                .map(|level| Node::empty_root(Level::from(level)))
                .collect(),
            Position::from(0),
        )
        .unwrap();
        let anchor = merkle_path.root(Node::from_cmu(&note.cmu())).into();

        let mut builder = sapling::builder::Builder::new(
            Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            anchor,
        );
        builder
            .add_spend(dfvk.fvk().clone(), note.clone(), merkle_path.clone())
            .unwrap();
        builder
            .add_output(
                Some(dfvk.to_ovk(Scope::External)),
                receiver,
                NoteValue::from_raw(VALUE),
                memo(MEMO),
            )
            .unwrap();
        let (bundle, meta) = builder
            .build::<MockSpendProver, MockOutputProver, _, ZatBalance>(
                core::slice::from_ref(sender),
                rng(1),
            )
            .unwrap()
            .unwrap();
        let bundle = bundle
            .create_proofs(&MockSpendProver, &MockOutputProver, rng(2), ())
            .apply_signatures(rng(3), [0; 32], &[sender.expsk().ask().clone()])
            .unwrap();

        let tx = TransactionData::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(0),
            None,
            None,
            Some(bundle),
            None,
        )
        .freeze()
        .unwrap();
        Payment {
            tx,
            spend_index: meta.spend_index(0).unwrap() as u32,
            output_index: meta.output_index(0).unwrap() as u32,
            spent: SpentNote::new(note, merkle_path),
        }
    }

    /// The Output Item for the payment, from the viewing keys of `keys`.
    fn item(&self, keys: &ExtendedSpendingKey) -> Item {
        let bundle = self.tx.sapling_bundle().unwrap();
        discover_sapling(
            &keys.to_diversifiable_full_viewing_key(),
            Zip212Enforcement::On,
            self.output_index,
            &bundle.shielded_outputs()[self.output_index as usize],
        )
        .unwrap()
        .item
    }

    /// A Signer Item of `sender` for the spend of the payment, before its signature.
    fn spend_signer(&self, sender: &ExtendedSpendingKey, address: SenderAddress) -> PreparedSigner {
        let bundle = self.tx.sapling_bundle().unwrap();
        prepare_sapling_spend(
            &*PROVER,
            rng(4),
            &sender.expsk().proof_generation_key(),
            self.spend_index,
            &bundle.shielded_spends()[self.spend_index as usize],
            self.spent.clone(),
            address,
        )
        .unwrap()
    }

    fn verify(&self, disclosure: &Disclosure) -> Result<crate::Report, VerifyError> {
        verify(
            &MainNetwork,
            BlockHeight::from_u32(HEIGHT),
            &self.tx,
            disclosure,
            Some(&spend_vk()),
        )
    }
}

fn message(text: &str) -> Message {
    Message::new(text.as_bytes().to_vec()).unwrap()
}

/// A signed Disclosure in which each of `signers` signs with its key.
fn signed(
    payment: &Payment,
    items: Vec<Item>,
    signers: &[(&PreparedSigner, &ExtendedSpendingKey)],
) -> Disclosure {
    let mut pending = PendingDisclosure::new(
        NetworkType::Main,
        payment.tx.txid(),
        items,
        Some(message("challenge 5f2a")),
        signers
            .iter()
            .map(|(prepared, _)| prepared.body().clone())
            .collect(),
    )
    .unwrap();
    for (prepared, key) in signers {
        pending.sign(rng(5), prepared, key.expsk().ask()).unwrap();
    }
    pending.finish().unwrap()
}

fn signer_error(kind: SignerKind, error: SignerError) -> VerifyError {
    VerifyError::Signer { kind, error }
}

#[test]
fn signed_disclosure_from_the_payer_verifies() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let prepared = payment.spend_signer(&sender, SenderAddress::Hidden);
    let disclosure = signed(
        &payment,
        vec![payment.item(&sender)],
        &[(&prepared, &sender)],
    );

    let encoded = disclosure.encode();
    assert!(encoded.starts_with("zds1"));
    let decoded = Disclosure::decode(&encoded).unwrap();
    assert_eq!(decoded, disclosure);

    let report = payment.verify(&decoded).unwrap();
    assert_eq!(report.class, Class::Signed);
    let note = report.items[0].1.as_ref().unwrap();
    assert_eq!(note.value, VALUE);
    assert_eq!(note.memo, memo(MEMO));

    let signed_report = report.signed.unwrap();
    assert!(signed_report.payer_proven());
    assert_eq!(signed_report.message(), Some(&message("challenge 5f2a")));
    let [SignerStatement::SpendAuthority(authority)] = signed_report.signers() else {
        panic!("one spend signer");
    };
    assert_eq!(authority.index(), payment.spend_index);
    assert_eq!(authority.address(), None);
    let spends = payment.tx.sapling_bundle().unwrap().shielded_spends().len();
    assert_eq!(signed_report.inputs_without_signer(), spends - 1);

    assert_eq!(
        verify(
            &MainNetwork,
            BlockHeight::from_u32(HEIGHT),
            &payment.tx,
            &decoded,
            None
        )
        .unwrap_err(),
        VerifyError::MissingSpendVerifyingKey
    );
}

#[test]
fn unsigned_disclosure_needs_no_verifying_key_and_proves_no_signer() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let disclosure = Disclosure::new(
        NetworkType::Main,
        payment.tx.txid(),
        vec![payment.item(&receiver)],
    )
    .unwrap();
    assert!(disclosure.encode().starts_with("zdu1"));

    let report = verify(
        &MainNetwork,
        BlockHeight::from_u32(HEIGHT),
        &payment.tx,
        &disclosure,
        None,
    )
    .unwrap();
    assert_eq!(report.class, Class::Unsigned);
    assert!(report.signed.is_none());
    assert_eq!(report.items[0].1.as_ref().unwrap().value, VALUE);
}

#[test]
fn signature_binds_the_message_the_items_and_the_network() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let prepared = payment.spend_signer(&sender, SenderAddress::Hidden);
    let disclosure = signed(
        &payment,
        vec![payment.item(&sender)],
        &[(&prepared, &sender)],
    );
    let invalid = signer_error(SignerKind::SaplingSpend, SignerError::InvalidSignature);

    let with = |network, items, text| {
        Disclosure::signed(
            network,
            disclosure.txid(),
            items,
            Some(message(text)),
            disclosure.signers().to_vec(),
        )
        .unwrap()
    };
    let items = disclosure.items().to_vec();

    let same = with(NetworkType::Main, items.clone(), "challenge 5f2a");
    assert!(payment.verify(&same).is_ok());

    let other_message = with(NetworkType::Main, items.clone(), "challenge 0000");
    assert_eq!(payment.verify(&other_message).unwrap_err(), invalid);

    let no_outputs = with(NetworkType::Main, vec![], "challenge 5f2a");
    assert_eq!(payment.verify(&no_outputs).unwrap_err(), invalid);

    let other_network = with(NetworkType::Test, items, "challenge 5f2a");
    assert_eq!(
        verify(
            &TestNetwork,
            BlockHeight::from_u32(HEIGHT),
            &payment.tx,
            &other_network,
            Some(&spend_vk())
        )
        .unwrap_err(),
        invalid
    );
}

#[test]
fn signed_disclosure_rejects_a_failed_output_item() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let prepared = payment.spend_signer(&sender, SenderAddress::Hidden);
    let mut item = payment.item(&sender);
    item.secret[0] ^= 1;
    let disclosure = signed(&payment, vec![item.clone()], &[(&prepared, &sender)]);

    assert_eq!(
        payment.verify(&disclosure).unwrap_err(),
        VerifyError::Item {
            kind: item.kind,
            index: item.index,
            error: ItemError::Rejected
        }
    );
}

#[test]
fn spend_signer_proves_its_address_and_its_spend() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let prepared = payment.spend_signer(&sender, SenderAddress::Revealed);
    assert_eq!(prepared.body().kind(), SignerKind::SaplingSpendWithAddress);
    let disclosure = signed(&payment, vec![], &[(&prepared, &sender)]);

    let report = payment.verify(&disclosure).unwrap();
    let signed_report = report.signed.unwrap();
    let [SignerStatement::SpendAuthority(authority)] = signed_report.signers() else {
        panic!("one spend signer");
    };
    assert_eq!(authority.address(), Some(&default_address(&sender)));

    let SignerBody::SaplingSpend(body) = prepared.body().clone() else {
        panic!("a spend signer");
    };
    let resigned = |body| {
        let altered = PreparedSigner {
            body: SignerBody::SaplingSpend(body),
            alpha: prepared.alpha,
        };
        payment
            .verify(&signed(&payment, vec![], &[(&altered, &sender)]))
            .unwrap_err()
    };
    let invalid_proof = signer_error(
        SignerKind::SaplingSpendWithAddress,
        SignerError::InvalidProof,
    );

    // A value commitment that the spend proof was not made for.
    let mut other_cv = body.clone();
    other_cv.cv = ValueCommitment::derive(
        NoteValue::from_raw(SPENT_VALUE),
        ValueCommitTrapdoor::random(rng(6)),
    )
    .to_bytes();
    assert_eq!(resigned(other_cv), invalid_proof);

    // An address proof that was made under another randomized key.
    let other_alpha = prepare_sapling_address_owner(
        &*PROVER,
        rng(7),
        &sender.expsk().proof_generation_key(),
        default_address(&sender),
    )
    .unwrap();
    let SignerBody::SaplingAddressOwner(owner) = other_alpha.body() else {
        panic!("an address owner signer");
    };
    let mut other_rk = body.clone();
    other_rk.address = Some(owner.address().clone());
    assert_eq!(resigned(other_rk), invalid_proof);

    // The identity, a point of small order, as cv.
    let mut small_order = body;
    small_order.cv = [0; 32];
    small_order.cv[0] = 0x01;
    assert_eq!(
        resigned(small_order),
        signer_error(SignerKind::SaplingSpendWithAddress, SignerError::InvalidCv)
    );
}

#[test]
fn receiver_signs_as_address_owner_next_to_the_payer() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let address = default_address(&receiver);
    let payment = Payment::new(&sender, address);
    let payer = payment.spend_signer(&sender, SenderAddress::Hidden);
    let owner = prepare_sapling_address_owner(
        &*PROVER,
        rng(8),
        &receiver.expsk().proof_generation_key(),
        address,
    )
    .unwrap();

    let item = payment.item(&receiver);
    let both = signed(
        &payment,
        vec![item.clone()],
        &[(&owner, &receiver), (&payer, &sender)],
    );
    let report = payment.verify(&both).unwrap().signed.unwrap();
    assert!(report.payer_proven());
    let [
        SignerStatement::SpendAuthority(_),
        SignerStatement::AddressOwner(owner_statement),
    ] = report.signers()
    else {
        panic!("a spend signer, then an address owner signer");
    };
    assert_eq!(owner_statement.address(), &address);
    assert_eq!(owner_statement.outputs(), &[payment.output_index]);

    let only_owner = signed(&payment, vec![item], &[(&owner, &receiver)]);
    let report = payment.verify(&only_owner).unwrap().signed.unwrap();
    assert!(!report.payer_proven());
    let spends = payment.tx.sapling_bundle().unwrap().shielded_spends().len();
    assert_eq!(report.inputs_without_signer(), spends);

    // The address must be the receiver of an output that the Disclosure lists.
    let no_output = signed(&payment, vec![], &[(&owner, &receiver)]);
    assert_eq!(
        payment.verify(&no_output).unwrap_err(),
        signer_error(
            SignerKind::SaplingAddressOwner,
            SignerError::AddressNotDisclosed
        )
    );
}

#[test]
fn signing_rejects_wrong_keys_and_missing_signatures() {
    let (sender, receiver) = (sapling_spending_key(1), sapling_spending_key(2));
    let payment = Payment::new(&sender, default_address(&receiver));
    let bundle = payment.tx.sapling_bundle().unwrap();

    // The receiver's key does not control the spent note or the sender's address.
    let receiver_key = receiver.expsk().proof_generation_key();
    assert_eq!(
        prepare_sapling_spend(
            &*PROVER,
            rng(4),
            &receiver_key,
            payment.spend_index,
            &bundle.shielded_spends()[payment.spend_index as usize],
            payment.spent.clone(),
            SenderAddress::Hidden,
        )
        .unwrap_err(),
        SignError::KeyMismatch
    );
    assert_eq!(
        prepare_sapling_address_owner(&*PROVER, rng(4), &receiver_key, default_address(&sender))
            .unwrap_err(),
        SignError::KeyMismatch
    );

    let prepared = payment.spend_signer(&sender, SenderAddress::Hidden);
    let pending = || {
        PendingDisclosure::new(
            NetworkType::Main,
            payment.tx.txid(),
            vec![payment.item(&sender)],
            None,
            vec![prepared.body().clone()],
        )
        .unwrap()
    };

    let mut wrong_key = pending();
    assert_eq!(
        wrong_key.sign(rng(5), &prepared, receiver.expsk().ask()),
        Err(SignError::InvalidSignature)
    );
    assert_eq!(
        wrong_key.finish().unwrap_err(),
        SignError::MissingSignature(SignerKind::SaplingSpend)
    );

    let mut other = PendingDisclosure::new(
        NetworkType::Main,
        payment.tx.txid(),
        vec![],
        None,
        vec![prepared.body().clone()],
    )
    .unwrap();
    assert_ne!(other.digest(), pending().digest());
    let unknown = PreparedSigner {
        body: SignerBody::SaplingSpend({
            let SignerBody::SaplingSpend(mut body) = prepared.body().clone() else {
                panic!("a spend signer");
            };
            body.index += 1;
            body
        }),
        alpha: prepared.alpha,
    };
    assert_eq!(
        other.sign(rng(5), &unknown, sender.expsk().ask()),
        Err(SignError::UnknownSigner)
    );

    assert_eq!(
        PendingDisclosure::new(NetworkType::Main, payment.tx.txid(), vec![], None, vec![])
            .unwrap_err(),
        FormatError::NoSigners
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn orchard_spend_signer_is_not_specified() {
    prepare_orchard_spend(0);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn ironwood_spend_signer_is_not_specified() {
    prepare_ironwood_spend(0);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn transparent_input_signer_is_not_specified() {
    prepare_transparent_input(0);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn orchard_address_owner_signer_is_not_specified() {
    prepare_orchard_address_owner(orchard_key(4).address_at(0u32, Scope::External));
}
