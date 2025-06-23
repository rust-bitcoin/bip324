// SPDX-License-Identifier: CC0-1.0

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
        .complete_materials(
            init_message.try_into().unwrap(),
            &mut resp_message[64..],
            None,
        )
        .unwrap();
    let mut init_finalize_message = vec![0u8; 36];
    init_handshake
        .complete_materials(
            resp_message[0..64].try_into().unwrap(),
            &mut init_finalize_message,
            None,
        )
        .unwrap();

    let mut packet_buffer = vec![0u8; 4096];
    init_handshake
        .authenticate_garbage_and_version(&resp_message[64..], &mut packet_buffer)
        .unwrap();
    resp_handshake
        .authenticate_garbage_and_version(&init_finalize_message, &mut packet_buffer)
        .unwrap();

    let mut alice = init_handshake.finalize().unwrap();
    let mut bob = resp_handshake.finalize().unwrap();

    // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
    let message = b"Hello world".to_vec();
    let packet_len = bip324::OutboundCipher::encryption_buffer_len(message.len());
    let mut encrypted_message_to_alice = vec![0u8; packet_len];
    bob.outbound()
        .encrypt(
            &message,
            &mut encrypted_message_to_alice,
            PacketType::Genuine,
            None,
        )
        .unwrap();

    let alice_message_len = alice
        .inbound()
        .decrypt_packet_len(encrypted_message_to_alice[..3].try_into().unwrap());
    let mut decrypted_message =
        vec![0u8; bip324::InboundCipher::decryption_buffer_len(alice_message_len)];
    alice
        .inbound()
        .decrypt(
            &encrypted_message_to_alice[3..],
            &mut decrypted_message,
            None,
        )
        .unwrap();
    assert_eq!(message, decrypted_message[1..].to_vec()); // Skip header byte

    let message = b"Goodbye!".to_vec();
    let packet_len = bip324::OutboundCipher::encryption_buffer_len(message.len());
    let mut encrypted_message_to_bob = vec![0u8; packet_len];
    alice
        .outbound()
        .encrypt(
            &message,
            &mut encrypted_message_to_bob,
            PacketType::Genuine,
            None,
        )
        .unwrap();

    let bob_message_len = bob
        .inbound()
        .decrypt_packet_len(encrypted_message_to_bob[..3].try_into().unwrap());
    let mut decrypted_message =
        vec![0u8; bip324::InboundCipher::decryption_buffer_len(bob_message_len)];
    bob.inbound()
        .decrypt(&encrypted_message_to_bob[3..], &mut decrypted_message, None)
        .unwrap();
    assert_eq!(message, decrypted_message[1..].to_vec()); // Skip header byte
}

#[test]
#[cfg(feature = "std")]
fn regtest_handshake() {
    use std::{
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bip324::{
        serde::{deserialize, serialize, NetworkMessage},
        Handshake, PacketType,
    };
    use bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags};
    let bitcoind = regtest_process(TransportVersion::V2);

    let mut stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();
    let mut public_key = [0u8; 64];
    let mut handshake = Handshake::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        None,
        &mut public_key,
    )
    .unwrap();
    println!("Writing public key to the remote node");
    stream.write_all(&public_key).unwrap();
    stream.flush().unwrap();
    let mut remote_public_key = [0u8; 64];
    println!("Reading the remote node public key");
    stream.read_exact(&mut remote_public_key).unwrap();
    let mut local_garbage_terminator_message = [0u8; 36];
    println!("Sending our garbage terminator");
    handshake
        .complete_materials(
            remote_public_key,
            &mut local_garbage_terminator_message,
            None,
        )
        .unwrap();
    stream.write_all(&local_garbage_terminator_message).unwrap();
    stream.flush().unwrap();
    let mut max_response = [0; 4096];
    println!("Reading the response buffer");
    let size = stream.read(&mut max_response).unwrap();
    let response = &mut max_response[..size];
    println!("Authenticating the handshake");
    let mut packet_buffer = vec![0u8; 4096];
    handshake
        .authenticate_garbage_and_version(response, &mut packet_buffer)
        .unwrap();
    println!("Finalizing the handshake");
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
    let packet_len = bip324::OutboundCipher::encryption_buffer_len(message.len());
    let mut packet = vec![0u8; packet_len];
    encrypter
        .encrypt(&message, &mut packet, PacketType::Genuine, None)
        .unwrap();
    println!("Serializing and writing version message");
    stream.write_all(&packet).unwrap();
    println!("Reading the response length buffer");
    let mut response_len = [0; 3];
    stream.read_exact(&mut response_len).unwrap();
    let message_len = decrypter.decrypt_packet_len(response_len);
    let mut response_message = vec![0; message_len];
    stream.read_exact(&mut response_message).unwrap();
    let mut decrypted_message =
        vec![0u8; bip324::InboundCipher::decryption_buffer_len(response_message.len())];
    let _ = decrypter
        .decrypt(&response_message, &mut decrypted_message, None)
        .unwrap();
    let message = deserialize(&decrypted_message[1..]).unwrap(); // Skip header byte
    assert_eq!(message.cmd(), "version");
}

#[test]
#[should_panic]
#[cfg(feature = "std")]
fn regtest_handshake_v1_only() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };

    use bip324::Handshake;
    let bitcoind = regtest_process(TransportVersion::V1);

    let mut stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();
    let mut public_key = [0u8; 64];
    let _ = Handshake::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        None,
        &mut public_key,
    )
    .unwrap();
    println!("Writing public key to the remote node");
    stream.write_all(&public_key).unwrap();
    stream.flush().unwrap();
    let mut remote_public_key = [0u8; 64];
    println!("Reading the remote node public key");
    stream.read_exact(&mut remote_public_key).unwrap();
}

/// Bitcoind transport versions.
enum TransportVersion {
    V1,
    V2,
}

/// Fire up a managed regtest bitcoind process.
fn regtest_process(transport: TransportVersion) -> bitcoind::Node {
    // Pull executable from auto-downloaded location, unless
    // environment variable override is present. Some operating
    // systems (e.g. NixOS) don't like the downloaded executable
    // so the environment varible must be used.
    let exe_path = bitcoind::exe_path().unwrap();
    println!("Using bitcoind at {exe_path}");
    let mut conf = bitcoind::Conf::default();

    // Enable V2 if requested, otherwise disable.
    match transport {
        TransportVersion::V2 => conf.args.push("-v2transport=1"),
        TransportVersion::V1 => conf.args.push("-v2transport=0"),
    }

    // Enable p2p port for tests.
    conf.p2p = bitcoind::P2P::Yes;
    bitcoind::Node::with_conf(exe_path, &conf).unwrap()
}
