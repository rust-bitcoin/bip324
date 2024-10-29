// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use bip324::{
    serde::{deserialize, serialize},
    AsyncProtocol, PacketType, ProtocolFailureSuggestion, Role,
};
use bip324_proxy::{V1ProtocolReader, V1ProtocolWriter};
use bitcoin::Network;
use log::{debug, error, info};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};

configure_me::include_config!();

/// A v1 to v1 proxy for use as a fallback.
async fn v1_proxy(client: TcpStream, network: Network) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client, network).await?;

    info!("Initialing remote connection {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip).await?;

    let (client_reader, client_writer) = client.into_split();
    let (remote_reader, remote_writer) = remote.into_split();

    let mut v1_client_reader = V1ProtocolReader::new(client_reader);
    let mut v1_client_writer = V1ProtocolWriter::new(network, client_writer);
    let mut v1_remote_reader = V1ProtocolReader::new(remote_reader);
    let mut v1_remote_writer = V1ProtocolWriter::new(network, remote_writer);

    info!("Setting up V1 proxy.");

    loop {
        select! {
            result = v1_client_reader.read() => {
                let msg = result?;
                debug!(
                    "Read {} message from client, writing to remote.",
                    msg.command()
                );
                v1_remote_writer.write(msg).await?;
            },
            result = v1_remote_reader.read() => {
                let msg = result?;
                debug!(
                    "Read {} message from remote, writing to client.",
                    msg.command()
                );
                v1_client_writer.write(msg).await?;
            },
        }
    }
}

/// Validate and bootstrap a v1 to v2 proxy connection.
async fn v2_proxy(
    client: TcpStream,
    network: Network,
    v1_fallback: bool,
) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client, network)
        .await
        .expect("peek address");

    info!("Reaching out to {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip)
        .await
        .expect("connect to remote");

    info!("Initiating handshake.");
    let (mut remote_reader, mut remote_writer) = remote.into_split();

    let protocol = match AsyncProtocol::new(
        network,
        Role::Initiator,
        None,
        None,
        &mut remote_reader,
        &mut remote_writer,
    )
    .await
    {
        Ok(p) => p,
        Err(bip324::ProtocolError::Io(_, ProtocolFailureSuggestion::RetryV1)) if v1_fallback => {
            info!("V2 protocol failed, falling back to V1...");
            return v1_proxy(client, network).await;
        }
        Err(e) => return Err(e.into()),
    };

    let (client_reader, client_writer) = client.into_split();
    let mut v1_client_reader = V1ProtocolReader::new(client_reader);
    let mut v1_client_writer = V1ProtocolWriter::new(network, client_writer);

    let (mut v2_remote_reader, mut v2_remote_writer) = protocol.into_split();

    info!("Setting up V2 proxy.");

    loop {
        select! {
            result = v1_client_reader.read() => {
                let msg = result?;
                debug!(
                    "Read {} message from client, writing to remote.",
                    msg.command()
                );

                let contents = serialize(msg).expect("serialize-able contents into network message");
                v2_remote_writer
                    .encrypt_and_write(&contents, &mut remote_writer)
                    .await
                    .expect("write to remote");
            },
            result = v2_remote_reader.read_and_decrypt(&mut remote_reader) => {
                let payload = result.expect("read packet");
                // Ignore decoy packets.
                if payload.packet_type() == PacketType::Genuine {
                    let msg = deserialize(payload.contents())
                        .expect("deserializable contents into network message");
                    debug!(
                        "Read {} message from remote, writing to client.",
                        msg.command()
                    );
                    v1_client_writer.write(msg).await.expect("write to client");
                }
            },
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    let network = Network::from_str(&config.network).expect("parse-able network");

    let local = TcpListener::bind((&*config.bind_host, config.bind_port))
        .await
        .expect("Failed to bind to proxy port.");
    info!(
        "Listening for connections on {}:{} with V1 fallback {}.",
        config.bind_host,
        config.bind_port,
        if config.v1_fallback {
            "enabled"
        } else {
            "disabled"
        },
    );
    loop {
        let (stream, _) = local
            .accept()
            .await
            .expect("Failed to accept inbound connection.");
        // Spawn a new task per connection.
        tokio::spawn(async move {
            match v2_proxy(stream, network, config.v1_fallback).await {
                Ok(_) => {
                    info!("Proxy establilshed.");
                }
                Err(e) => {
                    error!("Connection ended with error: {e}.");
                }
            };
        });
    }
}
