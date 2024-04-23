use bip324::{Handshake, Role};
use bitcoin::Network;

#[test]
#[cfg(feature = "std")]
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
    let encrypted_message_to_alice = bob
        .prepare_packet_with_alloc(&message, None, false)
        .unwrap();
    let messages = alice
        .decrypt_contents_with_alloc(&encrypted_message_to_alice[3..], None)
        .unwrap();
    assert_eq!(message, messages.message.unwrap());
    let message = b"Goodbye!".to_vec();
    let encrypted_message_to_bob = alice
        .prepare_packet_with_alloc(&message, None, false)
        .unwrap();
    let messages = bob
        .decrypt_contents_with_alloc(&encrypted_message_to_bob[3..], None)
        .unwrap();
    assert_eq!(message, messages.message.unwrap());
}
