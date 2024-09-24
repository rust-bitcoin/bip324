// SPDX-License-Identifier: MIT OR Apache-2.0

const RPC_USER: &str = "test";
const RPC_PASSWORD: &str = "b324";
const HOST: &str = "http://localhost:18443";
const PORT: u16 = 18444;

#[test]
#[cfg(feature = "std")]
fn hello_world_happy_path() {
    use bip324::{Handshake, PacketType, Role};
    use bitcoin::Network;

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
        .authenticate_garbage_and_version_with_alloc(&resp_message[64..])
        .unwrap();
    resp_handshake
        .authenticate_garbage_and_version_with_alloc(&init_finalize_message)
        .unwrap();

    let mut alice = init_handshake.finalize().unwrap();
    let mut bob = resp_handshake.finalize().unwrap();

    // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
    let message = b"Hello world".to_vec();
    let encrypted_message_to_alice = bob
        .packet_writer
        .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
        .unwrap();
    let messages = alice
        .packet_reader
        .decrypt_contents_with_alloc(&encrypted_message_to_alice[3..], None)
        .unwrap();
    assert_eq!(message, messages.unwrap());
    let message = b"Goodbye!".to_vec();
    let encrypted_message_to_bob = alice
        .packet_writer
        .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
        .unwrap();
    let messages = bob
        .packet_reader
        .decrypt_contents_with_alloc(&encrypted_message_to_bob[3..], None)
        .unwrap();
    assert_eq!(message, messages.unwrap());
}

#[test]
#[cfg(feature = "std")]
#[ignore = "CI"]
fn regtest_handshake() {
    use std::{
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use bip324::{
        serde::{deserialize, serialize, NetworkMessage},
        Handshake, PacketType,
    };
    use bitcoincore_rpc::{
        bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags},
        RpcApi,
    };

    let rpc = bitcoincore_rpc::Client::new(
        HOST,
        bitcoincore_rpc::Auth::UserPass(RPC_USER.into(), RPC_PASSWORD.into()),
    )
    .unwrap();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{PORT}")).unwrap();
    let mut public_key = [0u8; 64];
    let mut handshake = Handshake::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        None,
        &mut public_key,
    )
    .unwrap();
    dbg!("Writing public key to the remote node");
    stream.write_all(&public_key).unwrap();
    stream.flush().unwrap();
    let mut remote_public_key = [0u8; 64];
    dbg!("Reading the remote node public key");
    stream.read_exact(&mut remote_public_key).unwrap();
    let mut local_garbage_terminator_message = [0u8; 36];
    dbg!("Sending our garbage terminator");
    handshake
        .complete_materials(remote_public_key, &mut local_garbage_terminator_message)
        .unwrap();
    stream.write_all(&local_garbage_terminator_message).unwrap();
    stream.flush().unwrap();
    let mut max_response = [0; 4096];
    dbg!("Reading the response buffer");
    let size = stream.read(&mut max_response).unwrap();
    let response = &mut max_response[..size];
    dbg!("Authenticating the handshake");
    handshake
        .authenticate_garbage_and_version_with_alloc(response)
        .unwrap();
    dbg!("Finalizing the handshake");
    let packet_handler = handshake.finalize().unwrap();
    let (mut decrypter, mut encrypter) = packet_handler.into_split();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), PORT);
    let from_and_recv = Address::new(&ip, ServiceFlags::NONE);
    let msg = VersionMessage {
        version: 70015,
        services: ServiceFlags::NONE,
        timestamp: now as i64,
        receiver: from_and_recv.clone(),
        sender: from_and_recv,
        nonce: 1,
        user_agent: "BIP324 Client".to_string(),
        start_height: 0,
        relay: false,
    };
    let message = serialize(NetworkMessage::Version(msg)).unwrap();
    let packet = encrypter
        .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
        .unwrap();
    dbg!("Serializing and writing version message");
    stream.write_all(&packet).unwrap();
    dbg!("Reading the response length buffer");
    let mut response_len = [0; 3];
    stream.read_exact(&mut response_len).unwrap();
    let message_len = decrypter.decypt_len(response_len);
    let mut response_message = vec![0; message_len];
    stream.read_exact(&mut response_message).unwrap();
    let msg = decrypter
        .decrypt_contents_with_alloc(&response_message, None)
        .unwrap();
    let message = deserialize(&msg.unwrap()).unwrap();
    dbg!("{}", message.cmd());
    assert_eq!(message.cmd(), "version");
    rpc.stop().unwrap();
    std::thread::sleep(Duration::from_secs(1));
}
