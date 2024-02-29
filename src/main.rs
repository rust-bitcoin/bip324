use bip324::{
    initialize_v2_handshake, initiator_complete_v2_handshake, receive_v2_handshake,
    responder_complete_v2_handshake,
};
fn main() {
    // Alice starts a connection with Bob by making a pub/priv keypair and sending a message to Bob.
    let handshake_init = initialize_v2_handshake(None).unwrap();
    // Bob parses Alice's message, generates his pub/priv key, and sends a message back.
    let mut handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
    // Alice finishes her handshake by using her keys from earlier, and sending a final message to Bob.
    let alice_completion =
        initiator_complete_v2_handshake(handshake_response.message.clone(), handshake_init)
            .unwrap();
    // Bob checks Alice derived the correct keys for the session by authenticating her first message.
    responder_complete_v2_handshake(alice_completion.message.clone(), &mut handshake_response)
        .unwrap();
    // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
    let mut alice = alice_completion.packet_handler;
    let mut bob = handshake_response.packet_handler;
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
