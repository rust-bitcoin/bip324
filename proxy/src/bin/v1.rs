//! Simple V1 proxy to test hooking things up end to end.

use tokio::net::{TcpListener, TcpStream};
use tokio::select;

/// Validate and bootstrap proxy connection.
async fn proxy_conn(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Initialing remote connection {}.", remote_ip);
    let mut remote = TcpStream::connect(remote_ip).await?;

    let (mut client_reader, mut client_writer) = client.split();
    let (mut remote_reader, mut remote_writer) = remote.split();
    loop {
        select! {
            res = tokio::io::copy(&mut client_reader, &mut remote_writer) => {
                match res {
                    Ok(bytes) => {
                        println!("Responded to {} with {bytes} bytes.", remote_ip);
                        if bytes == 0 {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Client closed connection. Disconnecting.",
                            )));
                        }
                    },
                    Err(_) => {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Remote closed connection: Disconnecting.",
                        )));
                    },
                }
            },
            res = tokio::io::copy(&mut remote_reader, &mut client_writer) => {
                match res {
                    Ok(bytes) => {
                        println!("Responded to local with {bytes} bytes.");
                        if bytes == 0 {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Client closed connection. Disconnecting.",
                            )));
                        }
                    },
                    Err(_) => {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Client closed connection. Disconnecting.",
                        )));
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
