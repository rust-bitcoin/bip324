// SPDX-License-Identifier: MIT OR Apache-2.0
//! Simple V1 proxy to test hooking things up end to end.

use bip324_proxy::{read_v1, write_v1};
use tokio::net::{TcpListener, TcpStream};

configure_me::include_config!();

/// Validate and bootstrap proxy connection.
async fn proxy_conn(client: TcpStream) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Initialing remote connection {}.", remote_ip);
    let remote = TcpStream::connect(remote_ip).await?;

    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut remote_reader, mut remote_writer) = remote.into_split();

    println!("Setting up proxy loop.");

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
            write_v1(&mut remote_writer, msg)
                .await
                .expect("write to remote");
        }
    });

    tokio::spawn(async move {
        loop {
            let msg = read_v1(&mut remote_reader).await.expect("read from remote");
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
            match proxy_conn(stream).await {
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
