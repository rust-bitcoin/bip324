// SPDX-License-Identifier: MIT OR Apache-2.0

use core::panic;

use bip324::{Handshake, Role};
use bip324_proxy::{read_v1, read_v2, write_v1, write_v2};
use bitcoin::Network;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

configure_me::include_config!();

const HANDSHAKE_BUFFER_BYTES: usize = 4096;

/// Validate and bootstrap proxy connection.
async fn proxy_conn(client: TcpStream) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client)
        .await
        .expect("peek address");

    println!("Reaching out to {}.", remote_ip);
    let mut remote = TcpStream::connect(remote_ip)
        .await
        .expect("connect to remote");

    println!("Initiating handshake.");
    let mut local_material_message = vec![0u8; 64];
    let mut handshake = Handshake::new(
        Network::Bitcoin,
        Role::Initiator,
        None,
        &mut local_material_message,
    )
    .expect("generate handshake");

    remote
        .write_all(&local_material_message)
        .await
        .expect("send local materials");

    println!("Sent handshake to remote.");

    // 64 bytes ES.
    let mut remote_material_message = [0u8; 64];
    println!("Reading handshake response from remote.");
    remote
        .read_exact(&mut remote_material_message)
        .await
        .expect("read remote materials");

    println!("Completing materials.");
    let mut local_garbage_terminator_message = [0u8; 36];
    handshake
        .complete_materials(
            remote_material_message,
            &mut local_garbage_terminator_message,
        )
        .expect("complete materials");

    println!("Sending garbage terminator and version packet.");
    remote
        .write_all(&local_garbage_terminator_message)
        .await
        .expect("send garbage and version");

    // Keep pulling bytes from the buffer until the garbage is flushed.
    let mut remote_garbage_and_version_buffer = BytesMut::with_capacity(HANDSHAKE_BUFFER_BYTES);
    loop {
        println!("Authenticating garbage and version packet...");

        // Read from the remote, hopefully contains all garbage, decoy packets, and version packet.
        // BytesMut is keeping track of its internal posistion, so this read should only ever
        // extend the buffer on retries. Not overwrite it. The buffer will grow if required.
        if let Err(e) = remote
            .read_buf(&mut remote_garbage_and_version_buffer)
            .await
        {
            panic!("unable to read garbage {}", e)
        }

        // Attempt to authenticate the channel.
        match handshake
            .authenticate_garbage_and_version_with_alloc(&remote_garbage_and_version_buffer)
        {
            Ok(()) => {
                println!("Channel authenticated.");
                break;
            }
            Err(bip324::Error::MessageLengthTooSmall) => {
                // Attempt to pull more from the buffer and retry.
                continue;
            }
            Err(e) => panic!("unable to authenticate garbage and version {}", e),
        }
    }

    let packet_handler = handshake.finalize().expect("finished handshake");

    println!("Splitting channels.");
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let (mut decrypter, mut encrypter) = packet_handler.into_split();

    println!("Setting up proxy loops.");

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
            write_v2(&mut remote_writer, &mut encrypter, msg)
                .await
                .expect("write to remote");
        }
    });

    tokio::spawn(async move {
        loop {
            let msg = read_v2(&mut remote_reader, &mut decrypter)
                .await
                .expect("read from remote");
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
                    println!("Connection ended with error: {e}.");
                }
            };
        });
    }
}
