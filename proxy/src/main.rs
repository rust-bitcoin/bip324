use bip324::{Handshake, Network, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Validate and bootstrap proxy connection.
#[allow(clippy::unused_io_amount)]
async fn proxy_conn(client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Reaching out to {}.", remote_ip);
    let mut outbound = TcpStream::connect(remote_ip).await?;

    println!("Initiating handshake.");
    let mut local_material_message = vec![0u8; 64];
    let mut handshake = Handshake::new(
        Network::Mainnet,
        Role::Initiator,
        None,
        &mut local_material_message,
    )
    .unwrap();
    outbound.write_all(&local_material_message).await?;
    println!("Sent handshake to remote.");

    // 64 bytes ES.
    let mut remote_material_message = [0u8; 64];
    println!("Reading handshake response from remote.");
    outbound.read_exact(&mut remote_material_message).await?;

    println!("Completing materials.");
    let mut local_garbage_terminator_message = [0u8; 36];
    handshake
        .complete_materials(
            remote_material_message,
            &mut local_garbage_terminator_message,
        )
        .unwrap();

    println!("Sending garbage terminator and version packet.");
    outbound
        .write_all(&local_garbage_terminator_message)
        .await?;

    println!("Authenticating garbage and version packet.");
    let mut remote_garbage_and_version = vec![0u8; 5000];
    outbound.read(&mut remote_garbage_and_version).await?;
    handshake
        .authenticate_garbage_and_version(&remote_garbage_and_version)
        .expect("authenticated garbage");
    println!("Channel authenticated.");

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
