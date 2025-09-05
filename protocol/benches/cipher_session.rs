// SPDX-License-Identifier: CC0-1.0

#![feature(test)]

extern crate test;

use bip324::{
    CipherSession, GarbageResult, Handshake, InboundCipher, Initialized, OutboundCipher,
    PacketType, ReceivedKey, Role, VersionResult, NUM_LENGTH_BYTES,
};
use p2p::Magic;
use test::{black_box, Bencher};

fn create_cipher_session_pair() -> (CipherSession, CipherSession) {
    // Send Alice's key.
    let alice_handshake = Handshake::<Initialized>::new(Magic::BITCOIN, Role::Initiator).unwrap();
    let mut alice_key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let alice_handshake = alice_handshake
        .send_key(None, &mut alice_key_buffer)
        .unwrap();

    // Send Bob's key
    let bob_handshake = Handshake::<Initialized>::new(Magic::BITCOIN, Role::Responder).unwrap();
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

    // Alice receives Bob's version.
    // First handle Bob's garbage terminator
    let (mut alice_handshake, consumed) = match alice_handshake
        .receive_garbage(&bob_version_buffer)
        .unwrap()
    {
        GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        } => (handshake, consumed_bytes),
        GarbageResult::NeedMoreData(_) => panic!("Should have found garbage terminator"),
    };

    // Process Bob's version packet
    let remaining = &bob_version_buffer[consumed..];
    let packet_len = alice_handshake
        .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
        .unwrap();
    let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

    let alice = match alice_handshake.receive_version(&mut packet).unwrap() {
        VersionResult::Complete { cipher } => cipher,
        VersionResult::Decoy(_) => panic!("Should have completed"),
    };

    // Bob receives Alice's version.
    // First handle Alice's garbage terminator
    let (mut bob_handshake, consumed) = match bob_handshake
        .receive_garbage(&alice_version_buffer)
        .unwrap()
    {
        GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        } => (handshake, consumed_bytes),
        GarbageResult::NeedMoreData(_) => panic!("Should have found garbage terminator"),
    };

    // Process Alice's version packet
    let remaining = &alice_version_buffer[consumed..];
    let packet_len = bob_handshake
        .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
        .unwrap();
    let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

    let bob = match bob_handshake.receive_version(&mut packet).unwrap() {
        VersionResult::Complete { cipher } => cipher,
        VersionResult::Decoy(_) => panic!("Should have completed"),
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

        // Decrypt the length from first NUM_LENGTH_BYTES bytes (real-world step).
        let packet_length = bob.inbound().decrypt_packet_len(black_box(
            encrypted[0..NUM_LENGTH_BYTES].try_into().unwrap(),
        ));

        // Decrypt the payload using the decrypted length.
        let mut decrypted = vec![0u8; InboundCipher::decryption_buffer_len(packet_length)];
        bob.inbound()
            .decrypt(
                black_box(&encrypted[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_length]),
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

        // Decrypt the length from first NUM_LENGTH_BYTES bytes (real-world step).
        let packet_length = bob.inbound().decrypt_packet_len(black_box(
            encrypted[0..NUM_LENGTH_BYTES].try_into().unwrap(),
        ));

        // Decrypt the payload using the decrypted length.
        let mut decrypted = vec![0u8; InboundCipher::decryption_buffer_len(packet_length)];
        bob.inbound()
            .decrypt(
                black_box(&encrypted[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_length]),
                &mut decrypted,
                None,
            )
            .unwrap();

        // Ensure the final result isn't optimized away.
        black_box(decrypted)
    });
}
