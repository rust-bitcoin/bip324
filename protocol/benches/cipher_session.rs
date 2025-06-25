// SPDX-License-Identifier: CC0-1.0

#![feature(test)]

extern crate test;

use bip324::{
    CipherSession, Handshake, HandshakeAuthentication, InboundCipher, Initialized, Network,
    OutboundCipher, PacketType, ReceivedKey, Role, NUM_INITIAL_HANDSHAKE_BUFFER_BYTES,
};
use test::{black_box, Bencher};

fn create_cipher_session_pair() -> (CipherSession, CipherSession) {
    // Send Alice's key.
    let alice_handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
    let mut alice_key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let alice_handshake = alice_handshake
        .send_key(None, &mut alice_key_buffer)
        .unwrap();

    // Send Bob's key
    let bob_handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();
    let mut bob_key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let bob_handshake = bob_handshake.send_key(None, &mut bob_key_buffer).unwrap();

    // Alice receives Bob's key.
    let alice_handshake = alice_handshake
        .receive_key(bob_key_buffer.try_into().unwrap())
        .unwrap();

    // Bob receives Alice's key.
    let bob_handshake = bob_handshake
        .receive_key(alice_key_buffer.try_into().unwrap())
        .unwrap();

    // Alice sends version.
    let mut alice_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let alice_handshake = alice_handshake
        .send_version(&mut alice_version_buffer, None)
        .unwrap();

    // Bob sends version.
    let mut bob_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let bob_handshake = bob_handshake
        .send_version(&mut bob_version_buffer, None)
        .unwrap();

    let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES];

    // Alice receives Bob's version.
    let alice = match alice_handshake
        .receive_version(&bob_version_buffer, &mut packet_buffer)
        .unwrap()
    {
        HandshakeAuthentication::Complete { cipher, .. } => cipher,
        HandshakeAuthentication::NeedMoreData(_) => panic!("Should have completed"),
    };

    // Bob receives Alice's version.
    let bob = match bob_handshake
        .receive_version(&alice_version_buffer, &mut packet_buffer)
        .unwrap()
    {
        HandshakeAuthentication::Complete { cipher, .. } => cipher,
        HandshakeAuthentication::NeedMoreData(_) => panic!("Should have completed"),
    };

    (alice, bob)
}

#[bench]
fn bench_round_trip_small_packet(b: &mut Bencher) {
    let plaintext = b"Hello, World!"; // ~13 bytes.
    let (mut alice, mut bob) = create_cipher_session_pair();

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
    let (mut alice, mut bob) = create_cipher_session_pair();

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
