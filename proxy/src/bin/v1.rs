//! Simple V1 proxy to test hooking things up end to end.

use bip324_proxy::{read_v1, write_v1};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

/// Validate and bootstrap proxy connection.
async fn proxy_conn(mut client: TcpStream) -> Result<(), bip324_proxy::Error> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Initialing remote connection {}.", remote_ip);
    let mut remote = TcpStream::connect(remote_ip).await?;

    let (mut client_reader, mut client_writer) = client.split();
    let (mut remote_reader, mut remote_writer) = remote.split();

    println!("Setting up proxy loop.");
    loop {
        select! {
            res = read_v1(&mut client_reader) => {
                match res {
                    Ok(msg) => {
                         println!("Read {} message from client, writing to remote.", msg.cmd);
                         write_v1(&mut remote_writer, msg).await?;
                    },
                    Err(e) => {
                         return Err(e);
                    },
                }
            },
            res = read_v1(&mut remote_reader) => {
                match res {
                    Ok(msg) => {
                         println!("Read {} message from remote, writing to client.", msg.cmd);
                         write_v1(&mut client_writer, msg).await?;
                    },
                    Err(e) => {
                         return Err(e);
                    },
                }
            },
        }
    }
}

#[tokio::main]
async fn main() {
    let proxy = TcpListener::bind(bip324_proxy::DEFAULT_PROXY)
        .await
        .expect("Failed to bind to proxy port.");
    println!(
        "Listening for connections on {}",
        bip324_proxy::DEFAULT_PROXY
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
                    println!("Ended connection with no errors.");
                }
                Err(e) => {
                    println!("Ended connection with error: {e}.");
                }
            };
        });
    }
}
