//! Discovery of the outputs a set of viewing keys can disclose.

use std::collections::HashMap;

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use orchard::{
    Action,
    keys::{FullViewingKey, PreparedIncomingViewingKey as OrchardIvk},
    note_encryption::{IronwoodDomain, OrchardDomain},
};
use sapling::{
    Rseed,
    bundle::OutputDescription,
    keys::PreparedIncomingViewingKey as SaplingIvk,
    note_encryption::{SaplingDomain, Zip212Enforcement},
    zip32::DiversifiableFullViewingKey,
};
use zcash_note_encryption::{
    Domain, OUT_PLAINTEXT_SIZE, OutPlaintextBytes, ShieldedOutput, try_note_decryption,
    try_output_recovery_with_ovk, try_output_recovery_with_pkd_esk,
};
use zcash_primitives::transaction::{Transaction, components::sapling::zip212_enforcement};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::Scope;

use crate::encoding::{Item, Kind};

/// The viewing keys of one account, as a UFVK carries them.
#[derive(Clone, Copy, Debug, Default)]
pub struct ViewingKeys<'a> {
    /// The Sapling component.
    pub sapling: Option<&'a DiversifiableFullViewingKey>,
    /// The Orchard component. Ironwood uses the same key.
    pub orchard: Option<&'a FullViewingKey>,
}

/// Which side of an output the keys are on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The keys decrypted the output with an incoming viewing key.
    Receiver,
    /// The keys recovered the output with an outgoing viewing key.
    Sender,
}

/// An output the keys can disclose, with the Item that discloses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosable {
    /// The Item to put in a Disclosure.
    pub item: Item,
    /// The side the keys are on.
    pub role: Role,
    /// The key scope that opened the output. Disclosing an [`Scope::Internal`] output links it
    /// to every other change output of the account.
    pub scope: Scope,
    /// The note value in zatoshis.
    pub value: u64,
    /// Another output of this transaction to the same address carries the same secret.
    /// Disclosing this output would also open that one.
    pub secret_reused: bool,
}

const SCOPES: [Scope; 2] = [Scope::External, Scope::Internal];

/// Lists every output of `tx` that `keys` can disclose.
///
/// `height` is the height of the block that contains `tx`. The reuse check in
/// [`Disclosable::secret_reused`] covers this transaction only. A wallet extends it to the
/// other outputs it knows at the same address.
pub fn discover<P: Parameters>(
    params: &P,
    height: BlockHeight,
    tx: &Transaction,
    keys: ViewingKeys<'_>,
) -> Vec<Disclosable> {
    let mut found = vec![];

    if let (Some(dfvk), Some(bundle)) = (keys.sapling, tx.sapling_bundle()) {
        let zip212 = zip212_enforcement(params, height);
        for (index, output) in bundle.shielded_outputs().iter().enumerate() {
            found.extend(discover_sapling(dfvk, zip212, index as u32, output));
        }
    }
    if let Some(fvk) = keys.orchard {
        if let Some(bundle) = tx.orchard_bundle() {
            for (index, action) in bundle.actions().iter().enumerate() {
                found.extend(discover_action(fvk, Kind::Orchard, index as u32, action));
            }
        }
        if let Some(bundle) = tx.ironwood_bundle() {
            for (index, action) in bundle.actions().iter().enumerate() {
                found.extend(discover_action(fvk, Kind::Ironwood, index as u32, action));
            }
        }
    }

    let mut counts: HashMap<_, usize> = HashMap::new();
    for d in &found {
        *counts
            .entry((d.item.kind.pool(), d.item.pk_d, d.item.secret))
            .or_default() += 1;
    }
    for d in &mut found {
        d.secret_reused = counts[&(d.item.kind.pool(), d.item.pk_d, d.item.secret)] > 1;
    }
    found
}

/// Returns the Item for one Sapling output, when `dfvk` can open it.
///
/// For a note with lead byte `0x01` that the keys both sent and received, the sender's
/// [`Kind::SaplingLegacySender`] Item is returned, since it shows receivability.
pub fn discover_sapling<A>(
    dfvk: &DiversifiableFullViewingKey,
    zip212: Zip212Enforcement,
    index: u32,
    output: &OutputDescription<A>,
) -> Option<Disclosable> {
    let domain = SaplingDomain::new(zip212);
    match sapling_as_receiver(&domain, dfvk, index, output) {
        Some(found) if found.item.kind == Kind::Sapling => Some(found),
        received => sapling_as_sender(&domain, dfvk, index, output).or(received),
    }
}

fn sapling_as_receiver<A>(
    domain: &SaplingDomain,
    dfvk: &DiversifiableFullViewingKey,
    index: u32,
    output: &OutputDescription<A>,
) -> Option<Disclosable> {
    for scope in SCOPES {
        let ivk = SaplingIvk::new(&dfvk.to_ivk(scope));
        if let Some((note, address, _)) = try_note_decryption(domain, &ivk, output) {
            let pk_d = address.to_bytes()[11..]
                .try_into()
                .expect("43-byte address");
            let (kind, secret) = match note.rseed() {
                Rseed::AfterZip212(rseed) => (Kind::Sapling, *rseed),
                Rseed::BeforeZip212(_) => {
                    let ephemeral_key = output.ephemeral_key();
                    let epk = SaplingDomain::prepare_epk(SaplingDomain::epk(ephemeral_key)?);
                    let key =
                        SaplingDomain::kdf(SaplingDomain::ka_agree_dec(&ivk, &epk), ephemeral_key);
                    let k_enc = key.as_bytes()[..32].try_into().expect("32-byte key");
                    (Kind::SaplingLegacyReceiver, k_enc)
                }
            };
            return Some(disclosable(
                kind,
                index,
                pk_d,
                secret,
                Role::Receiver,
                scope,
                note.value().inner(),
            ));
        }
    }
    None
}

fn sapling_as_sender<A>(
    domain: &SaplingDomain,
    dfvk: &DiversifiableFullViewingKey,
    index: u32,
    output: &OutputDescription<A>,
) -> Option<Disclosable> {
    for scope in SCOPES {
        let ovk = dfvk.to_ovk(scope);
        let ock = SaplingDomain::derive_ock(
            &ovk,
            output.cv(),
            &output.cmu().to_bytes(),
            output.ephemeral_key(),
        );
        let Some(op) = decrypt_out_ciphertext(&ock.0, output.out_ciphertext()) else {
            continue;
        };
        let pk_d = SaplingDomain::extract_pk_d(&op)?;
        let esk = SaplingDomain::extract_esk(&op)?;
        let (note, _, _) = try_output_recovery_with_pkd_esk(domain, pk_d, esk, output)?;
        let pk_d = op.0[..32].try_into().expect("32-byte pk_d");
        let (kind, secret) = match note.rseed() {
            Rseed::AfterZip212(rseed) => (Kind::Sapling, *rseed),
            Rseed::BeforeZip212(_) => (
                Kind::SaplingLegacySender,
                op.0[32..].try_into().expect("32-byte esk"),
            ),
        };
        return Some(disclosable(
            kind,
            index,
            pk_d,
            secret,
            Role::Sender,
            scope,
            note.value().inner(),
        ));
    }
    None
}

/// Returns the Item for one Orchard or Ironwood action, when `fvk` can open it. `kind`
/// selects the pool the action belongs to.
pub fn discover_action<T>(
    fvk: &FullViewingKey,
    kind: Kind,
    index: u32,
    action: &Action<T>,
) -> Option<Disclosable> {
    match kind {
        Kind::Orchard => open_action(OrchardDomain::for_action(action), fvk, kind, index, action),
        Kind::Ironwood => open_action(IronwoodDomain::for_action(action), fvk, kind, index, action),
        _ => None,
    }
}

fn open_action<D, T>(
    domain: D,
    fvk: &FullViewingKey,
    kind: Kind,
    index: u32,
    action: &Action<T>,
) -> Option<Disclosable>
where
    D: Domain<
            Note = orchard::Note,
            Recipient = orchard::Address,
            IncomingViewingKey = OrchardIvk,
            OutgoingViewingKey = orchard::keys::OutgoingViewingKey,
            ValueCommitment = orchard::value::ValueCommitment,
        >,
    Action<T>: ShieldedOutput<D>,
{
    let opened = SCOPES
        .into_iter()
        .find_map(|scope| {
            let ivk = OrchardIvk::new(&fvk.to_ivk(scope));
            try_note_decryption(&domain, &ivk, action)
                .map(|(note, address, _)| (note, address, Role::Receiver, scope))
        })
        .or_else(|| {
            SCOPES.into_iter().find_map(|scope| {
                try_output_recovery_with_ovk(
                    &domain,
                    &fvk.to_ovk(scope),
                    action,
                    action.cv_net(),
                    &action.encrypted_note().out_ciphertext,
                )
                .map(|(note, address, _)| (note, address, Role::Sender, scope))
            })
        });

    opened.map(|(note, address, role, scope)| {
        let pk_d = address.to_raw_address_bytes()[11..]
            .try_into()
            .expect("43-byte address");
        disclosable(
            kind,
            index,
            pk_d,
            *note.rseed().as_bytes(),
            role,
            scope,
            note.value().inner(),
        )
    })
}

fn decrypt_out_ciphertext(ock: &[u8; 32], out_ciphertext: &[u8; 80]) -> Option<OutPlaintextBytes> {
    let mut op = [0; OUT_PLAINTEXT_SIZE];
    op.copy_from_slice(&out_ciphertext[..OUT_PLAINTEXT_SIZE]);
    ChaCha20Poly1305::new(Key::from_slice(ock))
        .decrypt_in_place_detached(
            Nonce::from_slice(&[0; 12]),
            &[],
            &mut op,
            Tag::from_slice(&out_ciphertext[OUT_PLAINTEXT_SIZE..]),
        )
        .ok()?;
    Some(OutPlaintextBytes(op))
}

fn disclosable(
    kind: Kind,
    index: u32,
    pk_d: [u8; 32],
    secret: [u8; 32],
    role: Role,
    scope: Scope,
    value: u64,
) -> Disclosable {
    Disclosable {
        item: Item {
            kind,
            index,
            pk_d,
            secret,
        },
        role,
        scope,
        value,
        secret_reused: false,
    }
}
