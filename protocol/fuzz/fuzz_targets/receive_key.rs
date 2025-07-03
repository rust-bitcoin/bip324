// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for the receive_key function.
//!
//! This focused test fuzzes the elliptic curve point validation and ECDH logic.

#![no_main]
use bip324::{Handshake, Initialized, Network, Role};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip if data is not exactly 64 bytes
    if data.len() != 64 {
        return;
    }

    // Set up a handshake in the SentKey state
    let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
    let mut key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let handshake = handshake.send_key(None, &mut key_buffer).unwrap();

    // Fuzz the receive_key function with arbitrary 64-byte data
    let mut key_bytes = [0u8; 64];
    key_bytes.copy_from_slice(data);

    match handshake.receive_key(key_bytes) {
        Ok(_handshake) => {
            // Successfully processed the key
            // This means:
            // 1. The 64 bytes represent a valid ElligatorSwift encoding
            // 2. The ECDH operation succeeded
            // 3. The key derivation worked
            // 4. It's not the V1 protocol magic bytes
        }
        Err(_) => {
            // Failed to process the key
            // This could be:
            // 1. Invalid ElligatorSwift encoding
            // 2. V1 protocol detected (first 4 bytes match network magic)
            // 3. ECDH or key derivation failure
        }
    }
});
