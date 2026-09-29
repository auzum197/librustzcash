//! Round trips through real bundles: `discover` produces an Item from viewing keys, and the
//! Verifier opens the same output with it.

use orchard::{
    bundle::{BundleVersion, Flags},
    keys::{FullViewingKey, Scope, SpendingKey},
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sapling::{
    note_encryption::Zip212Enforcement,
    prover::mock::{MockOutputProver, MockSpendProver},
    value::NoteValue,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};

use crate::{
    Item, ItemError, Kind, Role, discover_action, discover_sapling, verify_action,
    verify_sapling_output,
};

const VALUE: u64 = 250_000_000;

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
            memo("Invoice #2291"),
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
        assert_eq!(note.memo, memo("Invoice #2291"));
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
    assert_eq!(note.memo, memo("Invoice #2291"));
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
