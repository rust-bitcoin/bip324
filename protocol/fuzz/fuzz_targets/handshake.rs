// SPDX-License-Identifier: CC0-1.0

//! ## Expected Outcomes
//!
//! * Most runs will fail with invalid EC points or handshake failures.
//! * No panics, crashes, or memory safety issues should occur.
//! * The implementation should handle all inputs gracefully.

#![no_main]
use bip324::{
    Handshake, HandshakeAuthentication, Initialized, Network, ReceivedKey, Role,
    NUM_INITIAL_HANDSHAKE_BUFFER_BYTES,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small for a meaningful test.
    // We need at least 64 bytes for the public key and at
    // least 30 more for some interesting garbage, decoy, version bytes.
    if data.len() < 100 {
        return;
    }

    // Initiator side of the handshake.
    let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
    let mut initiator_pubkey = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let handshake = handshake.send_key(None, &mut initiator_pubkey).unwrap();

    // Use the first 64 bytes of fuzz data as the responder's public key.
    let mut fuzzed_responder_pubkey = [0u8; 64];
    fuzzed_responder_pubkey.copy_from_slice(&data[..64]);

    // Attempt to receive the fuzzed key.
    let handshake = match handshake.receive_key(fuzzed_responder_pubkey) {
        Ok(h) => h,
        Err(_) => return, // Invalid key rejected successfully.
    };

    // Send version message just to move the state of the handshake along.
    let mut version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let handshake = handshake.send_version(&mut version_buffer, None).unwrap();

    // Try to receive and authenticate the fuzzed garbage and version data.
    let garbage_and_version = Vec::from(&data[64..]);
    let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES];
    match handshake.receive_version(&garbage_and_version, &mut packet_buffer) {
        Ok(HandshakeAuthentication::Complete { .. }) => {
            // Handshake completed successfully.
            // This should only happen with some very lucky random bytes.
        }
        Ok(HandshakeAuthentication::NeedMoreData(_)) => {
            // Handshake needs more ciphertext.
            // This is an expected outcome for fuzzed inputs.
        }
        Err(_) => {
            // Authentication or parsing failed.
            // This is an expected outcome for fuzzed inputs.
        }
    }
});
