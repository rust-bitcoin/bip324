// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for the receive_version function.
//!
//! This focused test fuzzes only the version packet decryption logic.

#![no_main]
use bip324::{GarbageResult, Handshake, Initialized, Network, ReceivedKey, Role, VersionResult};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.is_empty() {
        return;
    }

    // Set up a valid handshake in the ReceivedGarbage state
    let initiator = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
    let mut initiator_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let initiator = initiator.send_key(None, &mut initiator_key).unwrap();

    let responder = Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();
    let mut responder_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let responder = responder.send_key(None, &mut responder_key).unwrap();

    // Exchange keys
    let initiator = initiator
        .receive_key(responder_key[..64].try_into().unwrap())
        .unwrap();
    let responder = responder
        .receive_key(initiator_key[..64].try_into().unwrap())
        .unwrap();

    // Both send version packets
    let mut initiator_version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let initiator = initiator
        .send_version(&mut initiator_version, None)
        .unwrap();

    let mut responder_version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let _responder = responder
        .send_version(&mut responder_version, None)
        .unwrap();

    // Process the responder's garbage terminator to get to ReceivedGarbage state
    let (handshake, _consumed) = match initiator.receive_garbage(&responder_version) {
        Ok(GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        }) => (handshake, consumed_bytes),
        _ => panic!("Should find garbage terminator in valid version buffer"),
    };

    // Now fuzz the receive_version function with arbitrary packet data
    let mut packet_data = data.to_vec();
    match handshake.receive_version(&mut packet_data) {
        Ok(VersionResult::Complete { cipher: _ }) => {
            // Successfully completed handshake
            // This should only happen with valid encrypted version packet
        }
        Ok(VersionResult::Decoy(_)) => {
            // Received a decoy packet
            // This should happen when packet type indicates decoy
        }
        Err(_) => {
            // Decryption or authentication failed
            // This is the most common outcome with random data
        }
    }
});
