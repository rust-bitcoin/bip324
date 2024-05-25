// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serialize and deserialize V2 messages over the wire.
//!
//! A subset of commands are represented with a single byte in V2 instead of the 12-byte ASCII encoding like V1. Message ID mappings are defined in [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki#user-content-v2_Bitcoin_P2P_message_structure).

use core::fmt;

use alloc::vec::Vec;
use bitcoin::{
    block,
    consensus::{encode, Decodable, Encodable},
    io::BufRead,
    VarInt,
};

pub use bitcoin::p2p::message::{CommandString, NetworkMessage};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Serialize,
    Deserialize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Serialize => write!(f, "Unable to serialize"),
            Error::Deserialize => write!(f, "Unable to deserialize"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Serialize => None,
            Error::Deserialize => None,
        }
    }
}

/// Serialize a [`NetworkMessage`] into a buffer.
pub fn serialize(msg: NetworkMessage) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    match &msg {
        NetworkMessage::Addr(_) => {
            buffer.push(1u8);
        }
        NetworkMessage::Inv(_) => {
            buffer.push(14u8);
        }
        NetworkMessage::GetData(_) => {
            buffer.push(11u8);
        }
        NetworkMessage::NotFound(_) => {
            buffer.push(17u8);
        }
        NetworkMessage::GetBlocks(_) => {
            buffer.push(9u8);
        }
        NetworkMessage::GetHeaders(_) => {
            buffer.push(12u8);
        }
        NetworkMessage::MemPool => {
            buffer.push(15u8);
        }
        NetworkMessage::Tx(_) => {
            buffer.push(21u8);
        }
        NetworkMessage::Block(_) => {
            buffer.push(2u8);
        }
        NetworkMessage::Headers(_) => {
            buffer.push(13u8);
        }
        NetworkMessage::Ping(_) => {
            buffer.push(18u8);
        }
        NetworkMessage::Pong(_) => {
            buffer.push(19u8);
        }
        NetworkMessage::MerkleBlock(_) => {
            buffer.push(16u8);
        }
        NetworkMessage::FilterLoad(_) => {
            buffer.push(8u8);
        }
        NetworkMessage::FilterAdd(_) => {
            buffer.push(6u8);
        }
        NetworkMessage::FilterClear => {
            buffer.push(7u8);
        }
        NetworkMessage::GetCFilters(_) => {
            buffer.push(22u8);
        }
        NetworkMessage::CFilter(_) => {
            buffer.push(23u8);
        }
        NetworkMessage::GetCFHeaders(_) => {
            buffer.push(24u8);
        }
        NetworkMessage::CFHeaders(_) => {
            buffer.push(25u8);
        }
        NetworkMessage::GetCFCheckpt(_) => {
            buffer.push(26u8);
        }
        NetworkMessage::CFCheckpt(_) => {
            buffer.push(27u8);
        }
        NetworkMessage::SendCmpct(_) => {
            buffer.push(20u8);
        }
        NetworkMessage::CmpctBlock(_) => {
            buffer.push(4u8);
        }
        NetworkMessage::GetBlockTxn(_) => {
            buffer.push(10u8);
        }
        NetworkMessage::BlockTxn(_) => {
            buffer.push(3u8);
        }
        NetworkMessage::FeeFilter(_) => {
            buffer.push(5u8);
        }
        NetworkMessage::AddrV2(_) => {
            buffer.push(28u8);
        }
        // Messages which are not optimized and use the zero-byte + 12 following bytes to encode command in ascii.
        NetworkMessage::Version(_)
        | NetworkMessage::Verack
        | NetworkMessage::SendHeaders
        | NetworkMessage::GetAddr
        | NetworkMessage::WtxidRelay
        | NetworkMessage::SendAddrV2
        | NetworkMessage::Alert(_)
        | NetworkMessage::Reject(_) => {
            buffer.push(0u8);
            msg.command()
                .consensus_encode(&mut buffer)
                .map_err(|_| Error::Serialize)?;
        }
        NetworkMessage::Unknown {
            command,
            payload: _,
        } => {
            buffer.push(0u8);
            command
                .consensus_encode(&mut buffer)
                .map_err(|_| Error::Serialize)?;
        }
    }

    msg.consensus_encode(&mut buffer)
        .map_err(|_| Error::Serialize)?;

    Ok(buffer)
}

/// Deserialize v2 message into [`NetworkMessage`].
pub fn deserialize(buffer: &[u8]) -> Result<NetworkMessage, Error> {
    let short_id = buffer[0];
    let mut payload_buffer = &buffer[1..];
    match short_id {
        // Zero-byte means the command is encoded in the next 12 bytes.
        0u8 => {
            // Next 12 bytes have encoded command.
            let mut command_buffer = &buffer[1..13];
            let command = CommandString::consensus_decode(&mut command_buffer)
                .map_err(|_| Error::Deserialize)?;
            // Rest of buffer is payload.
            payload_buffer = &buffer[13..];
            // There are a handful of "known" messages which don't use a short ID, otherwise Unknown.
            match command.as_ref() {
                "version" => Ok(NetworkMessage::Version(
                    Decodable::consensus_decode(&mut payload_buffer)
                        .map_err(|_| Error::Deserialize)?,
                )),
                "verack" => Ok(NetworkMessage::Verack),
                "sendheaders" => Ok(NetworkMessage::SendHeaders),
                "getaddr" => Ok(NetworkMessage::GetAddr),
                "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
                "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),
                "alert" => Ok(NetworkMessage::Alert(
                    Decodable::consensus_decode(&mut payload_buffer)
                        .map_err(|_| Error::Deserialize)?,
                )),
                "reject" => Ok(NetworkMessage::Reject(
                    Decodable::consensus_decode(&mut payload_buffer)
                        .map_err(|_| Error::Deserialize)?,
                )),
                _ => Ok(NetworkMessage::Unknown {
                    command,
                    payload: payload_buffer.to_vec(),
                }),
            }
        }
        // The following single byte IDs map to command short IDs.
        1u8 => Ok(NetworkMessage::Addr(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        2u8 => Ok(NetworkMessage::Block(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        3u8 => Ok(NetworkMessage::BlockTxn(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        4u8 => Ok(NetworkMessage::CmpctBlock(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        5u8 => Ok(NetworkMessage::FeeFilter(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        6u8 => Ok(NetworkMessage::FilterAdd(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        7u8 => Ok(NetworkMessage::FilterClear),
        8u8 => Ok(NetworkMessage::FilterLoad(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        9u8 => Ok(NetworkMessage::GetBlocks(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        10u8 => Ok(NetworkMessage::GetBlockTxn(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        11u8 => Ok(NetworkMessage::GetData(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        12u8 => Ok(NetworkMessage::GetHeaders(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        // This one gets a little weird and needs a bit of love in the future.
        13u8 => Ok(NetworkMessage::Headers(
            HeaderDeserializationWrapper::consensus_decode(&mut payload_buffer)
                .map_err(|_| Error::Deserialize)?
                .0,
        )),
        14u8 => Ok(NetworkMessage::Inv(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        15u8 => Ok(NetworkMessage::MemPool),
        16u8 => Ok(NetworkMessage::MerkleBlock(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        17u8 => Ok(NetworkMessage::NotFound(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        18u8 => Ok(NetworkMessage::Ping(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        19u8 => Ok(NetworkMessage::Pong(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        20u8 => Ok(NetworkMessage::SendCmpct(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        21u8 => Ok(NetworkMessage::Tx(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        22u8 => Ok(NetworkMessage::GetCFilters(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        23u8 => Ok(NetworkMessage::CFilter(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        24u8 => Ok(NetworkMessage::GetCFHeaders(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        25u8 => Ok(NetworkMessage::CFHeaders(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        26u8 => Ok(NetworkMessage::GetCFCheckpt(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        27u8 => Ok(NetworkMessage::CFCheckpt(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),
        28u8 => Ok(NetworkMessage::AddrV2(
            Decodable::consensus_decode(&mut payload_buffer).map_err(|_| Error::Deserialize)?,
        )),

        // Unsupported short ID.
        _ => Err(Error::Deserialize),
    }
}

// Copied from rust-bitcoin internals.
//
// Only the deserialized side needs to be copied over since
// the serialize side is applied at the NetworkMessage level.
struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(encode::Error::ParseFailed(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }
}
