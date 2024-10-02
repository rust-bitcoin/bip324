// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use bip324::{
    serde::{deserialize, serialize},
    AsyncProtocol, PacketType, Role,
};
use bip324_proxy::{V1ProtocolReader, V1ProtocolWriter};
use bitcoin::Network;
use log::{debug, error, info};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

configure_me::include_config!();

/// Validate and bootstrap proxy connection.
async fn proxy_conn(client: TcpStream, network: Network) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client, network)
        .await
        .expect("peek address");

    info!("Reaching out to {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip)
        .await
        .expect("connect to remote");

    info!("Initiating handshake.");
    let (remote_reader, remote_writer) = remote.into_split();
    // Convert to futures-compatible types.
    let remote_reader = remote_reader.compat();
    let remote_writer = remote_writer.compat_write();

    let protocol = AsyncProtocol::new(
        network,
        Role::Initiator,
        None,
        None,
        remote_reader,
        remote_writer,
    )
    .await
    .expect("protocol establishment");

    let (client_reader, client_writer) = client.into_split();
    let mut v1_client_reader = V1ProtocolReader::new(client_reader);
    let mut v1_client_writer = V1ProtocolWriter::new(network, client_writer);

    let (mut remote_reader, mut remote_writer) = protocol.into_split();

    info!("Setting up proxy.");

    loop {
        select! {
            result = v1_client_reader.read() => {
                let msg = result?;
                debug!(
                    "Read {} message from client, writing to remote.",
                    msg.command()
                );

                let contents = serialize(msg).expect("serialize-able contents into network message");
                remote_writer
                    .encrypt(&contents)
                    .await
                    .expect("write to remote");
            },
            result = remote_reader.decrypt() => {
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

    let proxy = TcpListener::bind((&*config.bind_host, config.bind_port))
        .await
        .expect("Failed to bind to proxy port.");
    info!(
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
                    info!("Proxy establilshed.");
                }
                Err(e) => {
                    error!("Connection ended with error: {e}.");
                }
            };
        });
    }
}
