//! Helper functions for bitcoin p2p proxies.
//!
//! The V1 and V2 p2p protocols have different header encodings, so a proxy has to do
//! a little more work than just encrypt/decrypt.

use std::fmt;
use std::net::SocketAddr;

use bip324::{PacketReader, PacketWriter};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::p2p::{Address, Magic};
use hex::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default to local host on port 1324.
pub const DEFAULT_PROXY: &str = "127.0.0.1:1324";
const DEFAULT_MAGIC: Magic = Magic::BITCOIN;
/// All V1 messages have a 24 byte header.
const V1_HEADER_BYTES: usize = 24;
/// Hex encoding of ascii version command.
const VERSION_COMMAND: [u8; 12] = [
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A subset of commands are represented with a single byte
/// in V2 instead of the 12-byte ASCII encoding like V1. The
/// indexes of the commands in the list corresponds to their
/// ID in the protocol, but needs +1 since the zero indexed
/// is reserved to indicated a 12-bytes representation.
const V2_SHORTID_COMMANDS: &[&str] = &[
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
];

/// An error occured while establishing the proxy connection or during the main loop.
#[derive(Debug)]
pub enum Error {
    WrongNetwork,
    WrongCommand,
    Network(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongNetwork => write!(f, "Recieved message on wrong network"),
            Error::Network(e) => write!(f, "Network error {}", e),
            Error::WrongCommand => write!(f, "Recieved message with wrong command"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Network(e) => Some(e),
            Error::WrongNetwork => None,
            Error::WrongCommand => None,
        }
    }
}

// Convert IO errors.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Network(e)
    }
}

/// Parsed message.
pub struct Message {
    pub cmd: String,
    pub payload: Vec<u8>,
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

    // Pull off address.
    let mut addr_bytes = &peek_bytes[44..];
    let remote_addr = Address::consensus_decode(&mut addr_bytes).expect("network address bytes");
    let socket_addr = remote_addr.socket_addr().expect("IP");

    Ok(socket_addr)
}

/// Read a network message off of the input stream.
pub async fn read_v1<T: AsyncRead + Unpin>(input: &mut T) -> Result<Message, Error> {
    let mut header_bytes = [0; V1_HEADER_BYTES];
    input.read_exact(&mut header_bytes).await?;

    let cmd = to_ascii(header_bytes[4..16].try_into().expect("12 bytes"));
    let payload_len = u32::from_le_bytes(
        header_bytes[16..20]
            .try_into()
            .expect("4 header length bytes"),
    );

    let mut payload = vec![0u8; payload_len as usize];
    input.read_exact(&mut payload).await?;

    Ok(Message { cmd, payload })
}

pub async fn read_v2<T: AsyncRead + Unpin>(
    input: &mut T,
    decrypter: &mut PacketReader,
) -> Result<Message, Error> {
    let mut length_bytes = [0u8; 3];
    input.read_exact(&mut length_bytes).await?;
    let packet_bytes_len = decrypter.decypt_len(length_bytes);
    let mut packet_bytes = vec![0u8; packet_bytes_len];
    input.read_exact(&mut packet_bytes).await?;

    // If packet is using short or full ID.
    let (cmd, cmd_index) = if packet_bytes.starts_with(&[0u8]) {
        (
            to_ascii(packet_bytes[1..13].try_into().expect("12 bytes")),
            13,
        )
    } else {
        (
            V2_SHORTID_COMMANDS[(packet_bytes[0] as u8 - 1) as usize].to_string(),
            1,
        )
    };

    let payload = packet_bytes[cmd_index..].to_vec();
    Ok(Message { cmd, payload })
}

/// Write the message to the output stream as a v1 packet.
pub async fn write_v1<T: AsyncWrite + Unpin>(output: &mut T, msg: Message) -> Result<(), Error> {
    let mut write_bytes = vec![];
    // 4 bytes of network magic.
    write_bytes.extend_from_slice(DEFAULT_MAGIC.to_bytes().as_slice());
    // 12 bytes for the command as encoded ascii.
    write_bytes.extend_from_slice(from_ascii(msg.cmd).as_slice());
    // 4 bytes for length, little endian.
    let length_bytes = (msg.payload.len() as u32).to_le_bytes();
    write_bytes.extend_from_slice(length_bytes.as_slice());
    // First 4 bytes of double sha256 digest is checksum.
    let checksum: [u8; 4] = sha256d::Hash::hash(msg.payload.as_slice()).as_byte_array()[..4]
        .try_into()
        .expect("4 byte checksum");
    write_bytes.extend_from_slice(checksum.as_slice());
    // Finally write the payload.
    write_bytes.extend_from_slice(msg.payload.as_slice());
    Ok(output.write_all(&write_bytes).await?)
}

/// Write the network message to the output stream.
pub async fn write_v2<T: AsyncWrite + Unpin>(
    output: &mut T,
    encrypter: &mut PacketWriter,
    msg: Message,
) -> Result<(), Error> {
    let mut contents = vec![];
    let shortid_index = V2_SHORTID_COMMANDS.iter().position(|w| w == &&msg.cmd[..]);
    match shortid_index {
        Some(id) => {
            let encoded_id = (id + 1) as u8;
            contents.push(encoded_id);
        }
        None => {
            contents.push(0u8);
            contents.extend_from_slice(from_ascii(msg.cmd).as_slice());
        }
    }

    contents.extend_from_slice(msg.payload.as_slice());
    let write_bytes = encrypter
        .prepare_v2_packet(contents, None, false)
        .expect("encryption");
    Ok(output.write_all(&write_bytes).await?)
}

fn to_ascii(bytes: [u8; 12]) -> String {
    String::from_utf8(bytes.to_vec())
        .expect("ascii")
        .trim_end_matches("00")
        .to_string()
}

fn from_ascii(ascii: String) -> [u8; 12] {
    let mut output_bytes = [0u8; 12];
    let cmd_bytes = ascii.as_bytes();
    output_bytes[0..cmd_bytes.len()].copy_from_slice(cmd_bytes);
    output_bytes
}
