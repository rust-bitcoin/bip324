use bip324::{Handshake, Network};

#[test]
fn hello_world_happy_path() {
    // Alice starts a connection with Bob by making a pub/priv keypair and sending a message to Bob.
    let mut init_message = vec![0u8; 64];
    let alice_handshake_init = Handshake::new(Network::Mainnet, None, &mut init_message).unwrap();

    // Bob parses Alice's message, generates his pub/priv key, and sends a message back.
    let bob_handshake_response =
        Handshake::new_from_request(Network::Mainnet, None, &init_message).unwrap();
    let mut response_message = vec![0u8; 100];
    let mut bob = bob_handshake_response
        .finalize(None, &mut response_message)
        .unwrap();

    // Alice finishes her handshake by using her keys from earlier, and sending a final message to Bob.
    let mut init_finalize_message = vec![0u8; 36];
    let mut alice = alice_handshake_init
        .finalize(
            Some(response_message[0..64].try_into().unwrap()),
            &mut init_finalize_message,
        )
        .unwrap();

    // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
    let message = b"Hello world".to_vec();
    let encrypted_message_to_alice = bob.prepare_v2_packet(message.clone(), None, false).unwrap();
    let messages = alice
        .receive_v2_packets(encrypted_message_to_alice, None)
        .unwrap();
    let secret_message = messages.first().unwrap().message.clone().unwrap();
    assert_eq!(message, secret_message);
    let message = b"Goodbye!".to_vec();
    let encrypted_message_to_bob = alice
        .prepare_v2_packet(message.clone(), None, false)
        .unwrap();
    let messages = bob
        .receive_v2_packets(encrypted_message_to_bob, None)
        .unwrap();
    let secret_message = messages.first().unwrap().message.clone().unwrap();
    assert_eq!(message, secret_message);
}
