use bip324::{Handshake, Network, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Validate and bootstrap proxy connection.
async fn proxy_conn(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Reaching out to {}.", remote_ip);
    let mut outbound = TcpStream::connect(remote_ip).await?;

    println!("Initiating handshake.");
    let mut message = vec![0u8; 64];
    let mut init_handshake =
        Handshake::new(Network::Mainnet, Role::Initiator, None, &mut message).unwrap();
    outbound.write_all(&message).await?;
    println!("Sent handshake to remote.");

    // 64 bytes ES.
    let mut material_message = vec![0u8; 64];
    println!("Reading handshake response from remote.");
    outbound.read_exact(&mut material_message).await?;

    println!("Completing materials.");
    let mut garbage_terminator_message = vec![0u8; 36];
    init_handshake
        .complete_materials(
            material_message.try_into().unwrap(),
            &mut garbage_terminator_message,
        )
        .unwrap();

    println!("Remote handshake accepted. Sending garbage terminator.");
    outbound.write_all(&garbage_terminator_message).await?;

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
