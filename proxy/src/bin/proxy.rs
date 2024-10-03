// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use bip324::{
    serde::{deserialize, serialize},
    AsyncProtocol, PacketType, Role,
};
use bip324_proxy::{read_v1, write_v1};
use bitcoin::Network;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

configure_me::include_config!();

/// Validate and bootstrap proxy connection.
async fn proxy_conn(client: TcpStream, network: Network) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client)
        .await
        .expect("peek address");

    println!("Reaching out to {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip)
        .await
        .expect("connect to remote");

    println!("Initiating handshake.");
    let (remote_reader, remote_writer) = remote.into_split();
    // Convert to futures-compatible types.
    let remote_reader = remote_reader.compat();
    let remote_writer = remote_writer.compat_write();

    let protocol = AsyncProtocol::new(network, Role::Initiator, None, remote_reader, remote_writer)
        .await
        .expect("protocol establishment");

    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut remote_reader, mut remote_writer) = protocol.into_split();

    println!("Setting up proxy.");

    // Spawning two threads instead of selecting on one due
    // to the IO calls not being cancellation safe. A select
    // drops other futures when one is ready, so it is
    // possible that it drops one with half read state.

    tokio::spawn(async move {
        loop {
            let msg = read_v1(&mut client_reader).await.expect("read from client");
            println!(
                "Read {} message from client, writing to remote.",
                msg.command()
            );
            let contents = serialize(msg).expect("serialize-able contents into network message");
            remote_writer
                .encrypt(&contents)
                .await
                .expect("write to remote");
        }
    });

    tokio::spawn(async move {
        loop {
            // Ignore any decoy packets.
            let payload = loop {
                let payload = remote_reader.decrypt().await.expect("read packet");

                if payload.packet_type() == PacketType::Genuine {
                    break payload;
                }
            };

            let msg = deserialize(payload.contents())
                .expect("deserializable contents into network message");
            println!(
                "Read {} message from remote, writing to client.",
                msg.command()
            );
            write_v1(&mut client_writer, msg)
                .await
                .expect("write to client");
        }
    });

    Ok(())
}

#[tokio::main]
async fn main() {
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    let network = Network::from_str(&config.network).expect("parse-able network");

    let proxy = TcpListener::bind((&*config.bind_host, config.bind_port))
        .await
        .expect("Failed to bind to proxy port.");
    println!(
        "Listening for connections on {}:{}",
        config.bind_host, config.bind_port,
    );
    loop {
        let (stream, _) = proxy
            .accept()
            .await
            .expect("Failed to accept inbound connection.");
        // Spawn a new task per connection.
        tokio::spawn(async move {
            match proxy_conn(stream, network).await {
                Ok(_) => {
                    println!("Proxy establilshed.");
                }
                Err(e) => {
                    println!("Connection ended with error: {e}.");
                }
            };
        });
    }
}
