use bip324::{Handshake, Role};
use bitcoin::Network;

#[test]
fn hello_world_happy_path() {
    let mut init_message = vec![0u8; 64];
    let mut init_handshake =
        Handshake::new(Network::Bitcoin, Role::Initiator, None, &mut init_message).unwrap();

    let mut resp_message = vec![0u8; 100];
    let mut resp_handshake =
        Handshake::new(Network::Bitcoin, Role::Responder, None, &mut resp_message).unwrap();

    resp_handshake
        .complete_materials(init_message.try_into().unwrap(), &mut resp_message[64..])
        .unwrap();
    let mut init_finalize_message = vec![0u8; 36];
    init_handshake
        .complete_materials(
            resp_message[0..64].try_into().unwrap(),
            &mut init_finalize_message,
        )
        .unwrap();

    init_handshake
        .authenticate_garbage_and_version(&resp_message[64..])
        .unwrap();
    resp_handshake
        .authenticate_garbage_and_version(&init_finalize_message)
        .unwrap();

    let mut alice = init_handshake.finalize().unwrap();
    let mut bob = resp_handshake.finalize().unwrap();

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
