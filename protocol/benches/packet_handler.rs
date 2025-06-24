#![feature(test)]

extern crate test;

use bip324::{CipherSession, Handshake, InboundCipher, Network, OutboundCipher, PacketType, Role};
use test::{black_box, Bencher};

fn create_packet_handler_pair() -> (CipherSession, CipherSession) {
    // Create a proper handshake between Alice and Bob.
    let mut alice_init_buffer = vec![0u8; 64];
    let mut alice_handshake = Handshake::new(
        Network::Bitcoin,
        Role::Initiator,
        None,
        &mut alice_init_buffer,
    )
    .unwrap();

    let mut bob_init_buffer = vec![0u8; 100];
    let mut bob_handshake = Handshake::new(
        Network::Bitcoin,
        Role::Responder,
        None,
        &mut bob_init_buffer,
    )
    .unwrap();

    // Bob completes materials with Alice's key.
    bob_handshake
        .complete_materials(
            alice_init_buffer[..64].try_into().unwrap(),
            &mut bob_init_buffer[64..],
            None,
        )
        .unwrap();

    // Alice completes materials with Bob's key.
    let mut alice_response_buffer = vec![0u8; 36];
    alice_handshake
        .complete_materials(
            bob_init_buffer[..64].try_into().unwrap(),
            &mut alice_response_buffer,
            None,
        )
        .unwrap();

    // Authenticate.
    let mut packet_buffer = vec![0u8; 4096];
    alice_handshake
        .authenticate_garbage_and_version(&bob_init_buffer[64..], &mut packet_buffer)
        .unwrap();
    bob_handshake
        .authenticate_garbage_and_version(&alice_response_buffer, &mut packet_buffer)
        .unwrap();

    let alice = alice_handshake.finalize().unwrap();
    let bob = bob_handshake.finalize().unwrap();

    (alice, bob)
}

#[bench]
fn bench_round_trip_small_packet(b: &mut Bencher) {
    let plaintext = b"Hello, World!"; // ~13 bytes.
    let (mut alice, mut bob) = create_packet_handler_pair();

    b.iter(|| {
        // Encrypt the packet.
        let packet_len = OutboundCipher::encryption_buffer_len(plaintext.len());
        let mut encrypted = vec![0u8; packet_len];
        alice
            .outbound()
            .encrypt(
                black_box(plaintext),
                &mut encrypted,
                PacketType::Genuine,
                None,
            )
            .unwrap();

        // Decrypt the length from first 3 bytes (real-world step).
        let packet_length = bob
            .inbound()
            .decrypt_packet_len(black_box(encrypted[0..3].try_into().unwrap()));

        // Decrypt the payload using the decrypted length.
        let mut decrypted = vec![0u8; InboundCipher::decryption_buffer_len(packet_length)];
        bob.inbound()
            .decrypt(
                black_box(&encrypted[3..3 + packet_length]),
                &mut decrypted,
                None,
            )
            .unwrap();

        // Ensure the final result isn't optimized away.
        black_box(decrypted)
    });
}

#[bench]
fn bench_round_trip_large_packet(b: &mut Bencher) {
    let plaintext = vec![0u8; 4096]; // 4KB packet.
    let (mut alice, mut bob) = create_packet_handler_pair();

    b.iter(|| {
        // Encrypt the packet.
        let packet_len = OutboundCipher::encryption_buffer_len(plaintext.len());
        let mut encrypted = vec![0u8; packet_len];
        alice
            .outbound()
            .encrypt(
                black_box(&plaintext),
                &mut encrypted,
                PacketType::Genuine,
                None,
            )
            .unwrap();

        // Decrypt the length from first 3 bytes (real-world step).
        let packet_length = bob
            .inbound()
            .decrypt_packet_len(black_box(encrypted[0..3].try_into().unwrap()));

        // Decrypt the payload using the decrypted length.
        let mut decrypted = vec![0u8; InboundCipher::decryption_buffer_len(packet_length)];
        bob.inbound()
            .decrypt(
                black_box(&encrypted[3..3 + packet_length]),
                &mut decrypted,
                None,
            )
            .unwrap();

        // Ensure the final result isn't optimized away.
        black_box(decrypted)
    });
}
