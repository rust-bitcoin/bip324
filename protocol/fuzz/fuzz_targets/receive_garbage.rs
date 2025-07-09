// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for the receive_garbage function.

#![no_main]
use bip324::{Handshake, Initialized, Network, ReceivedKey, Role};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;

fuzz_target!(|data: &[u8]| {
    // Cap input size to avoid wasting time on obviously invalid large inputs
    // The protocol limit is 4095 garbage bytes + 16 terminator bytes = 4111 total
    // Test up to ~5000 bytes to cover boundary cases
    if data.len() > 5000 {
        return;
    }

    // Use deterministic seeds for reproducible fuzzing
    let seed = [42u8; 32];
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let secp = secp256k1::Secp256k1::signing_only();

    // Set up a valid handshake in the SentVersion state
    let initiator =
        Handshake::<Initialized>::new_with_rng(Network::Bitcoin, Role::Initiator, &mut rng, &secp)
            .unwrap();
    let mut initiator_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let initiator = initiator.send_key(None, &mut initiator_key).unwrap();

    let mut rng2 = rand::rngs::StdRng::from_seed([43u8; 32]);
    let responder =
        Handshake::<Initialized>::new_with_rng(Network::Bitcoin, Role::Responder, &mut rng2, &secp)
            .unwrap();
    let mut responder_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let responder = responder.send_key(None, &mut responder_key).unwrap();

    // Exchange keys using real keys to get valid ECDH shared secrets
    let initiator = initiator
        .receive_key(responder_key[..64].try_into().unwrap())
        .unwrap();
    let responder = responder
        .receive_key(initiator_key[..64].try_into().unwrap())
        .unwrap();

    // Get the real responder's garbage terminator from responder's send_version output
    let mut responder_version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let _responder = responder
        .send_version(&mut responder_version, None)
        .unwrap();

    // The responder's garbage terminator is in the first 16 bytes of their version output
    let responder_terminator = &responder_version[..16];

    // Send version to reach SentVersion state
    let mut initiator_version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let initiator = initiator
        .send_version(&mut initiator_version, None)
        .unwrap();

    // Create realistic test case: fuzz_data + real_terminator
    let mut realistic_input = data.to_vec();
    realistic_input.extend_from_slice(responder_terminator);

    // Test the receive_garbage function with realistic input
    let _ = initiator.receive_garbage(&realistic_input);
});
