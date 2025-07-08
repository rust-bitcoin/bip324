// SPDX-License-Identifier: CC0-1.0

#[cfg(feature = "std")]
const PORT: u16 = 18444;

#[test]
#[cfg(feature = "std")]
fn hello_world_happy_path() {
    use bip324::{
        GarbageResult, Handshake, Initialized, PacketType, ReceivedKey, Role, VersionResult,
        NUM_LENGTH_BYTES,
    };
    use bitcoin::Network;

    // Create initiator handshake
    let init_handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();

    // Send initiator key
    let mut init_key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let init_handshake = init_handshake.send_key(None, &mut init_key_buffer).unwrap();

    // Create responder handshake
    let resp_handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();

    // Send responder key
    let mut resp_key_buffer = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let resp_handshake = resp_handshake.send_key(None, &mut resp_key_buffer).unwrap();

    // Initiator receives responder's key
    let init_handshake = init_handshake
        .receive_key(resp_key_buffer[..64].try_into().unwrap())
        .unwrap();

    // Responder receives initiator's key
    let resp_handshake = resp_handshake
        .receive_key(init_key_buffer[..64].try_into().unwrap())
        .unwrap();

    // Initiator sends version
    let mut init_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let init_handshake = init_handshake
        .send_version(&mut init_version_buffer, None)
        .unwrap();

    // Responder sends version
    let mut resp_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let resp_handshake = resp_handshake
        .send_version(&mut resp_version_buffer, None)
        .unwrap();

    // Initiator receives responder's garbage and version
    let (mut init_handshake, consumed) = match init_handshake
        .receive_garbage(&resp_version_buffer)
        .unwrap()
    {
        GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        } => (handshake, consumed_bytes),
        GarbageResult::NeedMoreData(_) => panic!("Should have found garbage"),
    };

    // Process the version packet properly
    let remaining = &resp_version_buffer[consumed..];
    let packet_len = init_handshake
        .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
        .unwrap();
    let mut version_packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let mut alice = match init_handshake.receive_version(&mut version_packet).unwrap() {
        VersionResult::Complete { cipher } => cipher,
        VersionResult::Decoy(_) => panic!("Should have completed"),
    };

    // Responder receives initiator's garbage and version
    let (mut resp_handshake, consumed) = match resp_handshake
        .receive_garbage(&init_version_buffer)
        .unwrap()
    {
        GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        } => (handshake, consumed_bytes),
        GarbageResult::NeedMoreData(_) => panic!("Should have found garbage"),
    };

    // Process the version packet properly
    let remaining = &init_version_buffer[consumed..];
    let packet_len = resp_handshake
        .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
        .unwrap();
    let mut version_packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let mut bob = match resp_handshake.receive_version(&mut version_packet).unwrap() {
        VersionResult::Complete { cipher } => cipher,
        VersionResult::Decoy(_) => panic!("Should have completed"),
    };

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

    let alice_message_len = alice.inbound().decrypt_packet_len(
        encrypted_message_to_alice[..NUM_LENGTH_BYTES]
            .try_into()
            .unwrap(),
    );
    let mut decrypted_message =
        vec![0u8; bip324::InboundCipher::decryption_buffer_len(alice_message_len)];
    alice
        .inbound()
        .decrypt(
            &encrypted_message_to_alice[NUM_LENGTH_BYTES..],
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

    let bob_message_len = bob.inbound().decrypt_packet_len(
        encrypted_message_to_bob[..NUM_LENGTH_BYTES]
            .try_into()
            .unwrap(),
    );
    let mut decrypted_message =
        vec![0u8; bip324::InboundCipher::decryption_buffer_len(bob_message_len)];
    bob.inbound()
        .decrypt(
            &encrypted_message_to_bob[NUM_LENGTH_BYTES..],
            &mut decrypted_message,
            None,
        )
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
        GarbageResult, Handshake, Initialized, PacketType, ReceivedKey, VersionResult,
        NUM_LENGTH_BYTES,
    };
    use bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags};
    let bitcoind = regtest_process(TransportVersion::V2);

    let mut stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();

    // Initialize handshake
    let handshake =
        Handshake::<Initialized>::new(bip324::Network::Regtest, bip324::Role::Initiator).unwrap();

    // Send our public key
    let mut public_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let handshake = handshake.send_key(None, &mut public_key).unwrap();
    println!("Writing public key to the remote node");
    stream.write_all(&public_key).unwrap();
    stream.flush().unwrap();

    // Read remote public key
    let mut remote_public_key = [0u8; 64];
    println!("Reading the remote node public key");
    stream.read_exact(&mut remote_public_key).unwrap();

    // Process remote key
    let handshake = handshake.receive_key(remote_public_key).unwrap();

    // Send garbage terminator and version
    let mut local_garbage_terminator_message =
        vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    println!("Sending our garbage terminator");
    let handshake = handshake
        .send_version(&mut local_garbage_terminator_message, None)
        .unwrap();
    stream.write_all(&local_garbage_terminator_message).unwrap();
    stream.flush().unwrap();

    // Read and authenticate remote response
    let mut max_response = [0; 4096];
    println!("Reading the response buffer");
    let size = stream.read(&mut max_response).unwrap();
    let response = &max_response[..size];
    println!("Authenticating the handshake");

    // First receive garbage
    let (mut handshake, consumed) = match handshake.receive_garbage(response).unwrap() {
        GarbageResult::FoundGarbage {
            handshake,
            consumed_bytes,
        } => {
            println!("Found garbage terminator after {consumed_bytes} bytes");
            (handshake, consumed_bytes)
        }
        GarbageResult::NeedMoreData(_) => panic!("Should have found garbage"),
    };

    // Then receive version - properly handle packet length and potential decoys.
    let mut remaining = &response[consumed..];
    let cipher_session = loop {
        // Check if we have enough data for packet length
        if remaining.len() < NUM_LENGTH_BYTES {
            panic!("Not enough data for packet length");
        }

        let packet_len = handshake
            .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
            .unwrap();

        if remaining.len() < NUM_LENGTH_BYTES + packet_len {
            panic!("Not enough data for full packet");
        }

        let mut version_packet =
            remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

        match handshake.receive_version(&mut version_packet).unwrap() {
            VersionResult::Complete { cipher } => {
                println!("Finalizing the handshake");
                break cipher;
            }
            VersionResult::Decoy(h) => {
                println!("Received decoy packet, continuing...");
                handshake = h;
                remaining = &remaining[NUM_LENGTH_BYTES + packet_len..];
                continue;
            }
        }
    };

    let (mut decrypter, mut encrypter) = cipher_session.into_split();
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
        user_agent: "BIP-324 Client".to_string(),
        start_height: 0,
        relay: false,
    };
    let message = serialize(NetworkMessage::Version(msg));
    let packet_len = bip324::OutboundCipher::encryption_buffer_len(message.len());
    let mut packet = vec![0u8; packet_len];
    encrypter
        .encrypt(&message, &mut packet, PacketType::Genuine, None)
        .unwrap();
    println!("Serializing and writing version message");
    stream.write_all(&packet).unwrap();
    println!("Reading the response length buffer");
    let mut response_len = [0; NUM_LENGTH_BYTES];
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
#[cfg(feature = "std")]
fn regtest_handshake_std() {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bip324::{
        io::Protocol,
        serde::{deserialize, serialize, NetworkMessage},
    };
    use bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags};

    let bitcoind = regtest_process(TransportVersion::V2);

    let stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();
    let reader = stream.try_clone().unwrap();
    let writer = stream;

    // Initialize high-level protocol with handshake
    println!("Starting BIP-324 handshake");
    let mut protocol = Protocol::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        None, // no garbage
        None, // no decoys
        reader,
        writer,
    )
    .unwrap();

    println!("Handshake completed successfully!");

    // Create version message.
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
        user_agent: "BIP-324 Client".to_string(),
        start_height: 0,
        relay: false,
    };

    let message = serialize(NetworkMessage::Version(msg));
    println!("Sending version message using Protocol::write()");
    protocol.write(&message).unwrap();

    println!("Reading version response using Protocol::read()");
    let payload = protocol.read().unwrap();

    let response_message = deserialize(payload.contents()).unwrap();
    assert_eq!(response_message.cmd(), "version");

    println!("Successfully exchanged version messages using Protocol API!");
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn regtest_handshake_async() {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bip324::{
        futures::Protocol,
        serde::{deserialize, serialize, NetworkMessage},
    };
    use bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags};
    use tokio::net::TcpStream;

    let bitcoind = regtest_process(TransportVersion::V2);

    let stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap())
        .await
        .unwrap();

    let (reader, writer) = stream.into_split();

    // Initialize high-level async protocol with handshake
    println!("Starting async BIP-324 handshake");
    let mut protocol = Protocol::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        None, // no garbage
        None, // no decoys
        reader,
        writer,
    )
    .await
    .unwrap();

    println!("Async handshake completed successfully!");

    // Create version message.
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
        user_agent: "BIP-324 Async Client".to_string(),
        start_height: 0,
        relay: false,
    };

    let message = serialize(NetworkMessage::Version(msg));
    println!("Sending version message using async Protocol::write()");
    protocol.write(&message).await.unwrap();

    println!("Reading version response using async Protocol::read()");
    let payload = protocol.read().await.unwrap();

    let response_message = deserialize(payload.contents()).unwrap();
    assert_eq!(response_message.cmd(), "version");

    println!("Successfully exchanged version messages using async Protocol API!");
}

#[test]
#[should_panic]
#[cfg(feature = "std")]
fn regtest_handshake_v1_only() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };

    use bip324::{Handshake, Initialized};
    let bitcoind = regtest_process(TransportVersion::V1);

    let mut stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();

    let handshake =
        Handshake::<Initialized>::new(bip324::Network::Regtest, bip324::Role::Initiator).unwrap();
    let mut public_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let _handshake = handshake.send_key(None, &mut public_key).unwrap();
    println!("Writing public key to the remote node");
    stream.write_all(&public_key).unwrap();
    stream.flush().unwrap();
    let mut remote_public_key = [0u8; 64];
    println!("Reading the remote node public key");
    stream.read_exact(&mut remote_public_key).unwrap();
}

/// Bitcoind transport versions.
#[cfg(feature = "std")]
enum TransportVersion {
    V1,
    V2,
}

/// Fire up a managed regtest bitcoind process.
#[cfg(feature = "std")]
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
