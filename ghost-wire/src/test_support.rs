//! Fixtures shared by this crate's tests: keys, stand-in key sets and accounts built
//! to a known point with the builders in `log_entries`.

use ed25519_dalek::SigningKey;
use rand::Rng;

use crate::account_key::{AccountKeySet, SealedCopy};
use crate::idlog::{validate_chain, validate_entry, LogEntry, LogState};
use crate::log_entries::{create_account_key, create_device_key, create_genesis, create_rotate_root};

pub(crate) fn random_key() -> SigningKey {
    let secret: [u8; 32] = rand::thread_rng().gen();
    SigningKey::from_bytes(&secret)
}

pub(crate) fn genesis_key_and_fp() -> (SigningKey, [u8; 32]) {
    let mk = random_key();
    let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();
    (mk, fp)
}

pub(crate) use crate::now_millis;

/// A set for the generation after `state`'s, with a stand-in copy for everyone
/// `state` must cover. Copies are not real HPKE output; this crate never opens them.
pub(crate) fn key_set_for(state: &LogState) -> AccountKeySet {
    AccountKeySet {
        account_fp: state.account_fp,
        generation: state.account_key().map_or(1, |k| k.generation + 1),
        copies: state
            .coverage()
            .into_iter()
            .map(|recipient| SealedCopy { recipient, encapsulated_key: [0x5A; 32], ciphertext: vec![0xA5; 48] })
            .collect(),
        back_link: None,
    }
}

/// The next account key generation for `state`, covering it, written by `authorizer`.
pub(crate) fn rekey(state: &LogState, authorizer: &SigningKey) -> (LogEntry, AccountKeySet) {
    let set = key_set_for(state);
    (create_account_key(state, authorizer, &random_key(), [0x77; 32], &set), set)
}

pub(crate) fn build_genesis() -> (LogState, SigningKey, SigningKey) {
    let (mk, _) = genesis_key_and_fp();
    let dk = random_key();
    let entry = create_genesis(&mk, &dk, "device-1");
    let state = validate_chain(&[entry]).unwrap();
    (state, mk, dk)
}

/// An account whose authority has moved to a recovery key: genesis, the device's
/// encryption key, a root rotation and the first account key.
pub(crate) struct Rotated {
    pub state: LogState,
    pub genesis: SigningKey,
    pub root: SigningKey,
    pub device: SigningKey,
    pub entries: Vec<LogEntry>,
}

pub(crate) fn build_rotated() -> Rotated {
    let (genesis, _) = genesis_key_and_fp();
    let device = random_key();
    let root = random_key();
    let mut entries = vec![create_genesis(&genesis, &device, "device-1")];
    let mut state = validate_chain(&entries).unwrap();
    let steps: [&dyn Fn(&LogState) -> LogEntry; 3] = [
        &|s| create_device_key(s, &device, &device, [0x01; 32]),
        &|s| create_rotate_root(s, &genesis, &root, [0x02; 32], &device),
        &|s| rekey(s, &device).0,
    ];
    for step in steps {
        let entry = step(&state);
        validate_entry(&mut state, &entry).unwrap();
        entries.push(entry);
    }
    Rotated { state, genesis, root, device, entries }
}
