// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helper functions for bitcoin p2p proxies.
//!
//! The V1 and V2 p2p protocols have different header encodings, so a proxy has to do
//! a little more work than just encrypt/decrypt. The [`NetworkMessage`]
//! type is the intermediate state for messages. The V1 side can use the RawNetworkMessage wrapper, but the V2 side
//! cannot since things like the checksum are not relevant (those responsibilites are pushed
//! onto the transport in V2).

use std::fmt;
use std::net::SocketAddr;

use bip324::serde::{deserialize, serialize};
use bip324::{PacketReader, PacketType, PacketWriter};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::{Address, Magic};
use hex::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_MAGIC: Magic = Magic::BITCOIN;
/// All V1 messages have a 24 byte header.
const V1_HEADER_BYTES: usize = 24;
/// Hex encoding of ascii version command.
const VERSION_COMMAND: [u8; 12] = [
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// An error occured while establishing the proxy connection or during the main loop.
#[derive(Debug)]
pub enum Error {
    WrongNetwork,
    WrongCommand,
    Serde,
    Network(std::io::Error),
    Cipher(bip324::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongNetwork => write!(f, "recieved message on wrong network"),
            Error::Network(e) => write!(f, "network {}", e),
            Error::WrongCommand => write!(f, "recieved message with wrong command"),
            Error::Cipher(e) => write!(f, "cipher encryption/decrytion error {}", e),
            Error::Serde => write!(f, "unable to serialize command"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Network(e) => Some(e),
            Error::WrongNetwork => None,
            Error::WrongCommand => None,
            Error::Cipher(e) => Some(e),
            Error::Serde => None,
        }
    }
}

impl From<bip324::Error> for Error {
    fn from(e: bip324::Error) -> Self {
        Error::Cipher(e)
    }
}

// Convert IO errors.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Network(e)
    }
}

/// Peek the input stream and pluck the remote address based on the version message.
pub async fn peek_addr(client: &TcpStream) -> Result<SocketAddr, Error> {
    println!("Validating client connection.");
    // Peek the first 70 bytes, 24 for the header and 46 for the first part of the version message.
    let mut peek_bytes = [0; 70];
    client.peek(&mut peek_bytes).await?;

    // Check network magic.
    println!("Got magic: {}", &peek_bytes[0..4].to_lower_hex_string());
    if DEFAULT_MAGIC.to_bytes().ne(&peek_bytes[0..4]) {
        return Err(Error::WrongNetwork);
    }

    // Check command.
    println!("Got command: {}", &peek_bytes[4..16].to_lower_hex_string());
    if VERSION_COMMAND.ne(&peek_bytes[4..16]) {
        return Err(Error::WrongCommand);
    }

    // Pull off address from the addr_recv field of the version message.
    let mut addr_bytes = &peek_bytes[44..];
    let remote_addr = Address::consensus_decode(&mut addr_bytes).expect("network address bytes");
    let socket_addr = remote_addr.socket_addr().expect("IP");

    Ok(socket_addr)
}

/// Read a v1 message off of the input stream.
///
/// This future is not cancellation safe since state is read multiple times and depends on read_exact.
pub async fn read_v1<T: AsyncRead + Unpin>(input: &mut T) -> Result<NetworkMessage, Error> {
    let mut header_bytes = [0u8; V1_HEADER_BYTES];
    input.read_exact(&mut header_bytes).await?;

    let payload_len = u32::from_le_bytes(
        header_bytes[16..20]
            .try_into()
            .expect("4 header length bytes"),
    );

    let mut full_bytes = vec![0u8; V1_HEADER_BYTES + payload_len as usize];
    full_bytes[0..V1_HEADER_BYTES].copy_from_slice(&header_bytes[..]);
    let payload_bytes = &mut full_bytes[V1_HEADER_BYTES..];
    input.read_exact(payload_bytes).await?;

    let message = RawNetworkMessage::consensus_decode(&mut &full_bytes[..]).expect("decode v1");
    // todo: drop this clone?
    Ok(message.payload().clone())
}

/// Read a v2 message off the input stream.
///
/// This future is not cancellation safe since state is read multiple times and depends on read_exact.
pub async fn read_v2<T: AsyncRead + Unpin>(
    input: &mut T,
    decrypter: &mut PacketReader,
) -> Result<NetworkMessage, Error> {
    // Ignore any decoy packets.
    let payload = loop {
        let mut length_bytes = [0u8; 3];
        input.read_exact(&mut length_bytes).await?;
        let packet_bytes_len = decrypter.decypt_len(length_bytes);
        let mut packet_bytes = vec![0u8; packet_bytes_len];
        input.read_exact(&mut packet_bytes).await?;
        let payload = decrypter.decrypt_payload_with_alloc(&packet_bytes, None)?;

        if payload.packet_type() == PacketType::Genuine {
            break payload;
        }
    };

    let message = deserialize(payload.contents()).map_err(|_| Error::Serde)?;
    Ok(message)
}

/// Write message to the output stream using v1.
pub async fn write_v1<T: AsyncWrite + Unpin>(
    output: &mut T,
    msg: NetworkMessage,
) -> Result<(), Error> {
    let raw = RawNetworkMessage::new(DEFAULT_MAGIC, msg);
    let mut buffer = vec![];
    raw.consensus_encode(&mut buffer)
        .map_err(|_| Error::Serde)?;
    output.write_all(&buffer[..]).await?;
    output.flush().await?;
    Ok(())
}

/// Write the network message to the output stream using v2.
pub async fn write_v2<T: AsyncWrite + Unpin>(
    output: &mut T,
    encrypter: &mut PacketWriter,
    msg: NetworkMessage,
) -> Result<(), Error> {
    let payload = serialize(msg).map_err(|_| Error::Serde)?;
    let write_bytes = encrypter
        .encrypt_packet_with_alloc(&payload, None, PacketType::Genuine)
        .expect("encryption");
    output.write_all(&write_bytes[..]).await?;
    output.flush().await?;
    Ok(())
}
