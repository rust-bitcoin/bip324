use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Validate and bootstrap proxy connection.
async fn proxy_conn(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Reaching out to {}.", remote_ip);
    let mut outbound = TcpStream::connect(remote_ip).await?;

    println!("Initiating handshake.");
    let handshake = initialize_v2_handshake(Some(0))?;
    outbound.write_all(&handshake.message).await?;
    println!("Sent handshake to remote.");

    // 64 bytes ES + 16 byte garbage terminator?
    let mut buffer = vec![0u8; 80];
    println!("Reading handshake response from remote.");
    outbound.read_exact(&mut buffer).await?;

    println!("Completing handshake.");
    let finish_handshake = initiator_complete_v2_handshake(buffer, handshake, true)?;
    println!("Remote handshake accepted. Sending garbage terminator.");
    outbound.write_all(&finish_handshake.message).await?;

    // TODO: setup read/write loop.
    Ok(())
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
