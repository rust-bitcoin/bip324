// SPDX-License-Identifier: MIT OR Apache-2.0
//! Simple V1 proxy to test hooking things up end to end.

use std::str::FromStr;

use bip324_proxy::{V1ProtocolReader, V1ProtocolWriter};
use bitcoin::Network;
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};

configure_me::include_config!();

/// Validate and bootstrap proxy connection.
async fn proxy_conn(client: TcpStream, network: Network) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client, network).await?;

    println!("Initialing remote connection {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip).await?;

    let (client_reader, client_writer) = client.into_split();
    let (remote_reader, remote_writer) = remote.into_split();

    let mut v1_client_reader = V1ProtocolReader::new(client_reader);
    let mut v1_client_writer = V1ProtocolWriter::new(network, client_writer);
    let mut v1_remote_reader = V1ProtocolReader::new(remote_reader);
    let mut v1_remote_writer = V1ProtocolWriter::new(network, remote_writer);

    println!("Setting up proxy loop.");

    loop {
        select! {
            result = v1_client_reader.read() => {
                let msg = result?;
                println!(
                    "Read {} message from client, writing to remote.",
                    msg.command()
                );
                v1_remote_writer.write(msg).await?;
            },
            result = v1_remote_reader.read() => {
                let msg = result?;
                println!(
                    "Read {} message from remote, writing to client.",
                    msg.command()
                );
                v1_client_writer.write(msg).await?;
            },
        }
    }
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
                    println!("Ended connection with error: {e}.");
                }
            };
        });
    }
}
