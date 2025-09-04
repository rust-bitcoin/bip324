// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the traffic shaping layer with bitcoind.

const PORT: u16 = 18444;

#[test]
fn sync_protocol_with_traffic_shaping() {
    use bip324::io::Payload;
    use bip324_traffic::{io::ShapedProtocol, DecoyStrategy, PaddingStrategy, TrafficConfig};
    use bitcoin::consensus::{deserialize, serialize};
    use p2p::{
        message::{NetworkMessage, V2NetworkMessage},
        message_network::{UserAgent, VersionMessage},
        Address, ProtocolVersion, ServiceFlags,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        time::{SystemTime, UNIX_EPOCH},
    };

    let bitcoind = regtest_process();

    let stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap()).unwrap();
    let reader = stream.try_clone().unwrap();
    let writer = stream;

    // Configure traffic shaping with both padding and decoys
    let config = TrafficConfig::new()
        .with_padding_strategy(PaddingStrategy::Random)
        .with_decoy_strategy(DecoyStrategy::Random);

    // Initialize traffic-shaped protocol with handshake
    println!("Starting BIP-324 handshake with traffic shaping");
    let mut protocol = ShapedProtocol::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        config,
        reader,
        writer,
    )
    .unwrap();

    println!("Handshake completed successfully with traffic shaping!");

    // Create version message
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), PORT);
    let from_and_recv = Address::new(&ip, ServiceFlags::NONE);
    let msg = VersionMessage {
        version: ProtocolVersion::INVALID_CB_NO_BAN_VERSION,
        services: ServiceFlags::NONE,
        timestamp: now as i64,
        receiver: from_and_recv.clone(),
        sender: from_and_recv,
        nonce: 1,
        user_agent: UserAgent::from_nonstandard("BIP-324 Traffic Shaping Test"),
        start_height: 0,
        relay: false,
    };

    // Send version message
    let version_message = NetworkMessage::Version(msg);
    let v2_version_message = V2NetworkMessage::new(version_message);
    println!("Sending version message with traffic shaping");
    protocol
        .write(&Payload::genuine(serialize(&v2_version_message)))
        .unwrap();

    // Read version response
    println!("Reading version response");
    let response = protocol.read().unwrap();
    let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
    assert_eq!(response_message.cmd(), "version");

    // Send verack
    let verack_message = NetworkMessage::Verack;
    let v2_verack_message = V2NetworkMessage::new(verack_message);
    println!("Sending verack with traffic shaping");
    protocol
        .write(&Payload::genuine(serialize(&v2_verack_message)))
        .unwrap();

    // Read verack response
    println!("Reading verack response");
    let response = protocol.read().unwrap();
    let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
    assert_eq!(response_message.cmd(), "verack");

    // Exchange a few ping/pong messages to verify the connection remains stable
    for i in 0..3 {
        let ping_message = NetworkMessage::Ping(i);
        let v2_ping_message = V2NetworkMessage::new(ping_message);
        println!("Sending ping {i} with traffic shaping");
        protocol
            .write(&Payload::genuine(serialize(&v2_ping_message)))
            .unwrap();

        // Read until we get a pong (might get other messages)
        loop {
            let response = protocol.read().unwrap();
            let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
            if response_message.cmd() == "pong" {
                println!("Received pong {i}");
                break;
            } else {
                println!(
                    "Received {} message, continuing to wait for pong",
                    response_message.cmd()
                );
            }
        }
    }

    println!("Successfully exchanged messages with traffic shaping enabled!");
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_protocol_with_traffic_shaping() {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bip324::io::Payload;
    use bip324_traffic::{futures::ShapedProtocol, DecoyStrategy, PaddingStrategy, TrafficConfig};
    use bitcoin::consensus::{deserialize, serialize};
    use p2p::{
        message::{NetworkMessage, V2NetworkMessage},
        message_network::{UserAgent, VersionMessage},
        Address, ProtocolVersion, ServiceFlags,
    };
    use tokio::net::TcpStream;

    let bitcoind = regtest_process();

    let stream = TcpStream::connect(bitcoind.params.p2p_socket.unwrap())
        .await
        .unwrap();

    let (reader, writer) = stream.into_split();

    // Configure traffic shaping with both padding and decoys
    let config = TrafficConfig::new()
        .with_padding_strategy(PaddingStrategy::Random)
        .with_decoy_strategy(DecoyStrategy::Random);

    // Initialize traffic-shaped async protocol with handshake
    println!("Starting async BIP-324 handshake with traffic shaping");
    let mut protocol = ShapedProtocol::new(
        bip324::Network::Regtest,
        bip324::Role::Initiator,
        config,
        reader,
        writer,
    )
    .await
    .unwrap();

    println!("Async handshake completed successfully with traffic shaping!");

    // Create version message
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), PORT);
    let from_and_recv = Address::new(&ip, ServiceFlags::NONE);
    let msg = VersionMessage {
        version: ProtocolVersion::INVALID_CB_NO_BAN_VERSION,
        services: ServiceFlags::NONE,
        timestamp: now as i64,
        receiver: from_and_recv.clone(),
        sender: from_and_recv,
        nonce: 1,
        user_agent: UserAgent::from_nonstandard("BIP-324 Async Traffic Shaping Test"),
        start_height: 0,
        relay: false,
    };

    // Send version message
    let version_message = NetworkMessage::Version(msg);
    let v2_version_message = V2NetworkMessage::new(version_message);
    println!("Sending version message with async traffic shaping");
    protocol
        .write(&Payload::genuine(serialize(&v2_version_message)))
        .await
        .unwrap();

    // Read version response
    println!("Reading version response");
    let response = protocol.read().await.unwrap();
    let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
    assert_eq!(response_message.cmd(), "version");

    // Send verack
    let verack_message = NetworkMessage::Verack;
    let v2_verack_message = V2NetworkMessage::new(verack_message);
    println!("Sending verack with async traffic shaping");
    protocol
        .write(&Payload::genuine(serialize(&v2_verack_message)))
        .await
        .unwrap();

    // Read verack response
    println!("Reading verack response");
    let response = protocol.read().await.unwrap();
    let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
    assert_eq!(response_message.cmd(), "verack");

    // Exchange a few ping/pong messages to verify the connection remains stable
    for i in 0..3 {
        let ping_message = NetworkMessage::Ping(i);
        let v2_ping_message = V2NetworkMessage::new(ping_message);
        println!("Sending async ping {i} with traffic shaping");
        protocol
            .write(&Payload::genuine(serialize(&v2_ping_message)))
            .await
            .unwrap();

        // Read until we get a pong (might get other messages)
        loop {
            let response = protocol.read().await.unwrap();
            let response_message: V2NetworkMessage = deserialize(response.contents()).unwrap();
            if response_message.cmd() == "pong" {
                println!("Received async pong {i}");
                break;
            } else {
                println!(
                    "Received {} message, continuing to wait for pong",
                    response_message.cmd()
                );
            }
        }
    }

    println!("Successfully exchanged async messages with traffic shaping enabled!");
}

/// Fire up a managed regtest bitcoind process.
fn regtest_process() -> bitcoind::Node {
    // Pull executable from auto-downloaded location, unless
    // environment variable override is present. Some operating
    // systems (e.g. NixOS) don't like the downloaded executable
    // so the environment variable must be used.
    let exe_path = bitcoind::exe_path().unwrap();
    println!("Using bitcoind at {exe_path}");
    // Enable v2 transport and p2p port for tests.
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-v2transport=1");
    conf.p2p = bitcoind::P2P::Yes;
    bitcoind::Node::with_conf(exe_path, &conf).unwrap()
}
