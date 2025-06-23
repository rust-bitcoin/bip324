#![no_main]
use bip324::{Handshake, Network, Role, NUM_INITIAL_HANDSHAKE_BUFFER_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small for an interesting test.
    if data.len() < 64 {
        return;
    }

    let mut initiator_pubkey = [0u8; 64];
    let mut handshake = Handshake::new(
        Network::Bitcoin,
        Role::Initiator,
        None,
        &mut initiator_pubkey,
    )
    .unwrap();

    let mut responder_pubkey = [0u8; 64];
    let _responder_handshake = Handshake::new(
        Network::Bitcoin,
        Role::Responder,
        None,
        &mut responder_pubkey,
    )
    .unwrap();

    // Create a mutation of the responder's bytes.
    let mut garbage_and_version = [0u8; 36];
    let copy_len = std::cmp::min(data.len(), garbage_and_version.len());
    garbage_and_version[..copy_len].copy_from_slice(&data[..copy_len]);

    // Create mutation of the responder's public key.
    // The key is either completely random or slightly tweaked.
    let mut fuzzed_responder_pubkey = [0u8; 64];
    if data.len() >= 128 {
        fuzzed_responder_pubkey.copy_from_slice(&data[64..128]);
    } else {
        fuzzed_responder_pubkey.copy_from_slice(&responder_pubkey);
        for (i, b) in data
            .iter()
            .enumerate()
            .take(fuzzed_responder_pubkey.len())
            .skip(copy_len)
        {
            fuzzed_responder_pubkey[i % 64] ^= b; // XOR to make controlled changes.
        }
    }

    // Try to complete the materials and authenticate with the fuzzed key and data.
    // Exercising malformed public key handling.
    let _ = handshake.complete_materials(fuzzed_responder_pubkey, &mut garbage_and_version, None);
    // Check how a broken handshake is handled.
    let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES]; // Initial buffer for decoy and version packets
    let _ = handshake.authenticate_garbage_and_version(&garbage_and_version, &mut packet_buffer);
    let _ = handshake.finalize();
});
