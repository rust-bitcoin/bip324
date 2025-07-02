// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for the receive_garbage function.
//!
//! This focused test fuzzes only the garbage terminator detection logic,
//! which is more effective than trying to fuzz the entire handshake.

#![no_main]
use bip324::{GarbageResult, Handshake, Initialized, Network, ReceivedKey, Role};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Set up a valid handshake in the SentVersion state
    let initiator = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
    let mut initiator_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let initiator = initiator.send_key(None, &mut initiator_key).unwrap();

    let responder = Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();
    let mut responder_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let responder = responder.send_key(None, &mut responder_key).unwrap();

    // Exchange keys using real keys to get valid ECDH shared secrets
    let initiator = initiator
        .receive_key(responder_key[..64].try_into().unwrap())
        .unwrap();
    let _responder = responder
        .receive_key(initiator_key[..64].try_into().unwrap())
        .unwrap();

    // Send version to reach SentVersion state
    let mut initiator_version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let initiator = initiator
        .send_version(&mut initiator_version, None)
        .unwrap();

    // Now fuzz the receive_garbage function with arbitrary data
    match initiator.receive_garbage(data) {
        Ok(GarbageResult::FoundGarbage {
            handshake: _,
            consumed_bytes,
        }) => {
            // Successfully found garbage terminator
            // Verify consumed_bytes is reasonable
            assert!(consumed_bytes <= data.len());
            assert!(consumed_bytes >= 16); // At least the terminator size

            // The garbage should be everything before the terminator
            let garbage_len = consumed_bytes - 16;
            assert!(garbage_len <= 4095); // Max garbage size
        }
        Ok(GarbageResult::NeedMoreData(_)) => {
            // Need more data - valid outcome for short inputs
            // This should happen when:
            // 1. Buffer is too short to contain terminator
            // 2. Buffer doesn't contain the terminator yet
        }
        Err(_) => {
            // Error parsing garbage - valid outcome
            // This should happen when:
            // 1. No terminator found within max garbage size
        }
    }
});
