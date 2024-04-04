use std::{error::Error, net::SocketAddr};

use bitcoin::consensus::Decodable;
use bitcoin::p2p::{Address, Magic};
use hex::prelude::*;
use tokio::net::TcpStream;

/// Default to local host on port 1324.
pub const DEFAULT_PROXY: &str = "127.0.0.1:1324";
/// Default to the signet network.
const DEFAULT_MAGIC: Magic = Magic::SIGNET;

/// Peek the input stream and pluck the remote address based on the version message.
pub async fn peek_addr(client: &TcpStream) -> Result<SocketAddr, Box<dyn Error>> {
    println!("Validating client connection.");
    // Peek the first 70 bytes, 24 for the header and 46 for the first part of the version message.
    let mut peek_bytes = [0; 70];
    let n = client.peek(&mut peek_bytes).await?;
    println!("Bytes read from local connection: {n}");
    println!("Got magic: {}", &peek_bytes[0..4].to_lower_hex_string());
    if DEFAULT_MAGIC.to_bytes().ne(&peek_bytes[0..4]) {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid magic.",
        )));
    }

    let mut addr_bytes = &peek_bytes[44..];
    let remote_addr = Address::consensus_decode(&mut addr_bytes).expect("network address bytes");
    let socket_addr = remote_addr.socket_addr().expect("IP");

    Ok(socket_addr)
}
