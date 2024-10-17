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

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Address;
use bitcoin::Network;
use hex::prelude::*;
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

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
    Io(std::io::Error),
    Protocol(bip324::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongNetwork => write!(f, "recieved message on wrong network"),
            Error::Io(e) => write!(f, "network {:?}", e),
            Error::WrongCommand => write!(f, "recieved message with wrong command"),
            Error::Protocol(e) => write!(f, "protocol error {:?}", e),
            Error::Serde => write!(f, "unable to serialize command"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bip324::Error> for Error {
    fn from(e: bip324::Error) -> Self {
        Error::Protocol(e)
    }
}

// Convert IO errors.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Peek the input stream and pluck the remote address based on the version message.
pub async fn peek_addr(client: &TcpStream, network: Network) -> Result<SocketAddr, Error> {
    // Peek the first 70 bytes, 24 for the header and 46 for the first part of the version message.
    let mut peek_bytes = [0; 70];
    client.peek(&mut peek_bytes).await?;

    // Check network magic.
    debug!("Got magic: {}", &peek_bytes[0..4].to_lower_hex_string());
    if network.magic().to_bytes().ne(&peek_bytes[0..4]) {
        return Err(Error::WrongNetwork);
    }

    // Check command.
    debug!("Got command: {}", &peek_bytes[4..16].to_lower_hex_string());
    if VERSION_COMMAND.ne(&peek_bytes[4..16]) {
        return Err(Error::WrongCommand);
    }

    // Pull off address from the addr_recv field of the version message.
    let mut addr_bytes = &peek_bytes[44..];
    let remote_addr = Address::consensus_decode(&mut addr_bytes).expect("network address bytes");
    let socket_addr = remote_addr.socket_addr().expect("ip address");

    Ok(socket_addr)
}

/// State machine of an asynchronous helps make functions cancellation safe.
#[derive(Debug)]
enum ReadState {
    ReadingLength {
        header_bytes: [u8; V1_HEADER_BYTES],
        bytes_read: usize,
    },
    ReadingPayload {
        packet_bytes: Vec<u8>,
        bytes_read: usize,
    },
}

impl Default for ReadState {
    fn default() -> Self {
        ReadState::ReadingLength {
            header_bytes: [0u8; V1_HEADER_BYTES],
            bytes_read: 0,
        }
    }
}

/// Read messages on the V1 protocol.
pub struct V1ProtocolReader<T: AsyncRead + Unpin> {
    input: T,
    state: ReadState,
}

impl<T: AsyncRead + Unpin> V1ProtocolReader<T> {
    /// New V1 message reader.
    pub fn new(input: T) -> Self {
        Self {
            input,
            state: ReadState::default(),
        }
    }

    /// Read a v1 message off of the input stream.
    pub async fn read(&mut self) -> Result<NetworkMessage, Error> {
        loop {
            match &mut self.state {
                ReadState::ReadingLength {
                    header_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < V1_HEADER_BYTES {
                        let n = self.input.read(&mut header_bytes[*bytes_read..]).await?;
                        *bytes_read += n;
                    }

                    let payload_len = u32::from_le_bytes(
                        header_bytes[16..20]
                            .try_into()
                            .expect("4 header length bytes"),
                    ) as usize;

                    let mut packet_bytes = vec![0u8; V1_HEADER_BYTES + payload_len];
                    packet_bytes[..V1_HEADER_BYTES].copy_from_slice(header_bytes);

                    self.state = ReadState::ReadingPayload {
                        packet_bytes,
                        bytes_read: V1_HEADER_BYTES,
                    };
                }
                ReadState::ReadingPayload {
                    packet_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < packet_bytes.len() {
                        let n = self.input.read(&mut packet_bytes[*bytes_read..]).await?;
                        *bytes_read += n;
                    }

                    let message = RawNetworkMessage::consensus_decode(&mut &packet_bytes[..])
                        .expect("decode v1");

                    self.state = ReadState::default();
                    // The RawNetworkMessage type doesn't have a nice way to pull
                    // out the payload, so using a clone here.
                    return Ok(message.payload().clone());
                }
            }
        }
    }
}

/// Write messages on the V1 protocol.
pub struct V1ProtocolWriter<T: AsyncWrite + Unpin> {
    network: Network,
    output: T,
}

impl<T: AsyncWrite + Unpin> V1ProtocolWriter<T> {
    /// New V1 message writer.
    pub fn new(network: Network, output: T) -> Self {
        Self { network, output }
    }

    /// Write message to the output stream using v1.
    pub async fn write(&mut self, msg: NetworkMessage) -> Result<(), Error> {
        let raw = RawNetworkMessage::new(self.network.magic(), msg);
        let mut buffer = vec![];
        raw.consensus_encode(&mut buffer)
            .map_err(|_| Error::Serde)?;
        self.output.write_all(&buffer[..]).await?;
        self.output.flush().await?;
        Ok(())
    }
}
