// SPDX-License-Identifier: CC0-1.0

//! BIP-324 encrypted transport protocol for Bitcoin P2P communication.
//!
//! This crate implements the [BIP-324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
//! version 2 encrypted transport protocol, which provides encryption and authentication
//! for bitcoin p2p connections. Like TLS, it begins with a handshake establishing shared
//! secrets, then encrypts all subsequent communication.
//!
//! # Quick Start
//!
//! For a complete encrypted connection, use the high-level APIs in the [`io`] or [`futures`] modules:
//!
//! ## Synchronous API (requires `std` feature)
//!
//! ```no_run
//! use bip324::io::Protocol;
//! use bip324::serde::{serialize, deserialize, NetworkMessage};
//! use std::net::TcpStream;
//! use std::io::BufReader;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let stream = TcpStream::connect("127.0.0.1:8333")?;
//!
//! // Wrap reader in BufReader for efficiency (protocol makes many small reads)
//! let reader = BufReader::new(stream.try_clone()?);
//! let writer = stream;
//!
//! let mut protocol = Protocol::new(
//!     bip324::Network::Bitcoin,
//!     bip324::Role::Initiator,
//!     None, None, // no garbage or decoys
//!     reader,
//!     writer,
//! )?;
//!
//! let ping_msg = NetworkMessage::Ping(0xdeadbeef);
//! let serialized = serialize(ping_msg);
//! protocol.write(&serialized)?;
//!
//! let response = protocol.read()?;
//! let response_msg: NetworkMessage = deserialize(&response.contents())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Asynchronous API (requires `tokio` feature)
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use bip324::futures::Protocol;
//! use bip324::serde::{serialize, deserialize, NetworkMessage};
//! use tokio::net::TcpStream;
//! use tokio::io::BufReader;
//!
//! let stream = TcpStream::connect("127.0.0.1:8333").await?;
//! let (reader, writer) = stream.into_split();
//!
//! // Wrap reader in BufReader for efficiency (protocol makes many small reads)
//! let buffered_reader = BufReader::new(reader);
//!
//! let mut protocol = Protocol::new(
//!     bip324::Network::Bitcoin,
//!     bip324::Role::Initiator,
//!     None, None, // no garbage or decoys
//!     buffered_reader,
//!     writer,
//! ).await?;
//!
//! let ping_msg = NetworkMessage::Ping(12345); // nonce
//! let serialized = serialize(ping_msg);
//! protocol.write(&serialized).await?;
//!
//! let response = protocol.read().await?;
//! let response_msg: NetworkMessage = deserialize(&response.contents())?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "tokio"))]
//! # fn main() {}
//! ```
//!
//! # Message Serialization
//!
//! BIP-324 introduces specific changes to how bitcoin P2P messages are serialized for V2 transport.
//! The [`serde`] module provides these serialization functions.
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use bip324::serde::{serialize, deserialize, NetworkMessage};
//!
//! let ping_msg = NetworkMessage::Ping(0xdeadbeef);
//! let serialized = serialize(ping_msg);
//!
//! let received_bytes = vec![0x12, 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0];
//! let message: NetworkMessage = deserialize(&received_bytes)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```
//!
//! # Performance Considerations
//!
//! The BIP-324 protocol makes multiple small reads, particularly during the handshake
//! (reading 64-byte keys, 16-byte terminators) and for each message (3-byte length prefix).
//! For optimal performance, wrap your reader in a `BufReader`:
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn sync_example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::BufReader;
//! use std::net::TcpStream;
//!
//! let stream = TcpStream::connect("127.0.0.1:8333")?;
//! let buffered_reader = BufReader::new(stream.try_clone()?);
//! # Ok(())
//! # }
//! ```
//!
//! # Advanced Usage
//!
//! For more control, such as no-std environments, you can use the lower level components.
//!
//! - [`Handshake`] - Type-safe handshake state machine.
//! - [`CipherSession`] - Managed encryption/decryption after handshake.
//!
//! # Protocol Details
//!
//! After the initial handshake, all data is encrypted in packets.
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | Length | 3 bytes | Encrypted length of contents |
//! | Header | 1 byte | Protocol flags including decoy indicator |
//! | Contents | Variable | The serialized message |
//! | Tag | 16 bytes | Authentication tag |
//!
//! The protocol supports both genuine packets containing application data and decoy
//! packets with random data for traffic analysis resistance.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod fschacha20poly1305;
#[cfg(feature = "tokio")]
pub mod futures;
mod handshake;
#[cfg(feature = "std")]
pub mod io;
#[cfg(feature = "std")]
pub mod serde;

use core::fmt;

use bitcoin::secp256k1::{
    self,
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    SecretKey,
};
use bitcoin_hashes::{hkdf, sha256, Hkdf};

pub use bitcoin::Network;

pub use handshake::{
    GarbageResult, Handshake, Initialized, ReceivedGarbage, ReceivedKey, SentKey, SentVersion,
    VersionResult,
};

use fschacha20poly1305::{FSChaCha20, FSChaCha20Poly1305};

/// Value for header byte with the decoy flag flipped to true.
pub const DECOY_BYTE: u8 = 128;
/// Number of bytes for the header holding protocol flags.
pub const NUM_HEADER_BYTES: usize = 1;
/// Number of bytes for the encrypted length prefix of a packet.
pub const NUM_LENGTH_BYTES: usize = 3;

// Number of bytes in elligator swift key.
const NUM_ELLIGATOR_SWIFT_BYTES: usize = 64;
// Number of bytes for the garbage terminator.
const NUM_GARBAGE_TERMINTOR_BYTES: usize = 16;
// Number of bytes for the authentication tag of a packet.
const NUM_TAG_BYTES: usize = 16;
// Number of bytes per packet for static layout, everything not including contents.
const NUM_PACKET_OVERHEAD_BYTES: usize = NUM_LENGTH_BYTES + NUM_HEADER_BYTES + NUM_TAG_BYTES;
// Version content is always empty for the current version of the protocol.
const VERSION_CONTENT: [u8; 0] = [];

/// Errors encountered throughout the lifetime of a V2 connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encrypted text does not contain enough information to decrypt.
    CiphertextTooSmall,
    /// Allocated memory is too small for packet, returns
    /// total required bytes for the failed packet so the
    /// caller can re-allocate and re-attempt.
    BufferTooSmall { required_bytes: usize },
    /// Tried to send more garbage bytes before terminator than allowed by spec.
    TooMuchGarbage,
    /// The remote sent the maximum amount of garbage bytes without
    /// a garbage terminator in the handshake.
    NoGarbageTerminator,
    /// The remote peer is communicating on the V1 protocol.
    V1Protocol,
    /// Not able to generate secret material.
    SecretGeneration(SecretGenerationError),
    /// General decryption error, channel could be out of sync.
    Decryption(fschacha20poly1305::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CiphertextTooSmall => {
                write!(
                    f,
                    "Ciphertext does not contain enough information, should be further extended."
                )
            }
            Error::BufferTooSmall { required_bytes } => write!(
                f,
                "Buffer memory allocation too small, need at least {required_bytes} bytes."
            ),
            Error::NoGarbageTerminator => {
                write!(f, "More than 4095 bytes of garbage recieved in the handshake before a terminator was sent.")
            }
            Error::SecretGeneration(e) => write!(f, "Cannot generate secrets: {e:?}."),
            Error::Decryption(e) => write!(f, "Decrytion error: {e:?}."),
            Error::V1Protocol => write!(f, "The remote peer is communicating on the V1 protocol."),
            Error::TooMuchGarbage => write!(
                f,
                "Tried to send more than 4095 bytes of garbage in handshake."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::CiphertextTooSmall => None,
            Error::BufferTooSmall { .. } => None,
            Error::NoGarbageTerminator => None,
            Error::V1Protocol => None,
            Error::SecretGeneration(e) => Some(e),
            Error::Decryption(e) => Some(e),
            Error::TooMuchGarbage => None,
        }
    }
}

impl From<fschacha20poly1305::Error> for Error {
    fn from(e: fschacha20poly1305::Error) -> Self {
        Error::Decryption(e)
    }
}

/// Secret generation specific errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecretGenerationError {
    /// Undable to generate a secret.
    MaterialsGeneration(secp256k1::Error),
    /// Unable to expand the key.
    Expansion(hkdf::MaxLengthError),
}

impl fmt::Display for SecretGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretGenerationError::MaterialsGeneration(e) => {
                write!(f, "Cannot generate materials: {e}.")
            }
            SecretGenerationError::Expansion(e) => write!(f, "Cannot expand key: {e}."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretGenerationError::MaterialsGeneration(e) => Some(e),
            SecretGenerationError::Expansion(e) => Some(e),
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::SecretGeneration(SecretGenerationError::MaterialsGeneration(e))
    }
}

impl From<hkdf::MaxLengthError> for Error {
    fn from(e: hkdf::MaxLengthError) -> Self {
        Error::SecretGeneration(SecretGenerationError::Expansion(e))
    }
}

/// All keys derived from the ECDH.
#[derive(Clone)]
pub struct SessionKeyMaterial {
    /// A unique ID to identify a connection.
    pub session_id: [u8; 32],
    initiator_length_key: [u8; 32],
    initiator_packet_key: [u8; 32],
    responder_length_key: [u8; 32],
    responder_packet_key: [u8; 32],
    initiator_garbage_terminator: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
    responder_garbage_terminator: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
}

impl SessionKeyMaterial {
    /// Derive session key material from ECDH shared secret.
    ///
    /// # Arguments
    ///
    /// * `a` - First party's ElligatorSwift public key.
    /// * `b` - Second party's ElligatorSwift public key.
    /// * `secret` - The secret key of the party calling this method.
    /// * `party` - Whether the caller is party A or B in the ECDH.
    /// * `network` - The Bitcoin network for key derivation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the derived session key material.
    ///
    /// # Errors
    ///
    /// * `SecretGeneration` - If key derivation fails.
    pub fn from_ecdh(
        a: ElligatorSwift,
        b: ElligatorSwift,
        secret: SecretKey,
        party: ElligatorSwiftParty,
        network: Network,
    ) -> Result<Self, Error> {
        let data = "bip324_ellswift_xonly_ecdh".as_bytes();
        let ecdh_sk = ElligatorSwift::shared_secret(a, b, secret, party, Some(data));

        let ikm_salt = "bitcoin_v2_shared_secret".as_bytes();
        let magic = network.magic().to_bytes();
        let salt = [ikm_salt, &magic].concat();
        let hk = Hkdf::<sha256::Hash>::new(salt.as_slice(), ecdh_sk.as_secret_bytes());
        let mut session_id = [0u8; 32];
        let session_info = "session_id".as_bytes();
        hk.expand(session_info, &mut session_id)?;
        let mut initiator_length_key = [0u8; 32];
        let intiiator_l_info = "initiator_L".as_bytes();
        hk.expand(intiiator_l_info, &mut initiator_length_key)?;
        let mut initiator_packet_key = [0u8; 32];
        let intiiator_p_info = "initiator_P".as_bytes();
        hk.expand(intiiator_p_info, &mut initiator_packet_key)?;
        let mut responder_length_key = [0u8; 32];
        let responder_l_info = "responder_L".as_bytes();
        hk.expand(responder_l_info, &mut responder_length_key)?;
        let mut responder_packet_key = [0u8; 32];
        let responder_p_info = "responder_P".as_bytes();
        hk.expand(responder_p_info, &mut responder_packet_key)?;
        let mut garbage = [0u8; 32];
        let garbage_info = "garbage_terminators".as_bytes();
        hk.expand(garbage_info, &mut garbage)?;
        let initiator_garbage_terminator: [u8; 16] = garbage[..16]
            .try_into()
            .expect("first 16 btyes of expanded garbage");
        let responder_garbage_terminator: [u8; 16] = garbage[16..]
            .try_into()
            .expect("last 16 bytes of expanded garbage");
        Ok(SessionKeyMaterial {
            session_id,
            initiator_length_key,
            initiator_packet_key,
            responder_length_key,
            responder_packet_key,
            initiator_garbage_terminator,
            responder_garbage_terminator,
        })
    }
}

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Started the handshake with a peer.
    Initiator,
    /// Responding to a handshake.
    Responder,
}

/// A decoy packet contains bogus information, but can be
/// used to hide the shape of the data being communicated
/// over an encrypted channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Genuine packet contains information.
    Genuine,
    /// Decoy packet contains bogus information.
    Decoy,
}

impl PacketType {
    /// Check if header byte has the decoy flag flipped.
    pub fn from_byte(header: &u8) -> Self {
        if header == &DECOY_BYTE {
            PacketType::Decoy
        } else {
            PacketType::Genuine
        }
    }

    /// Returns header byte based on the type.
    pub fn to_byte(&self) -> u8 {
        match self {
            PacketType::Genuine => 0,
            PacketType::Decoy => DECOY_BYTE,
        }
    }
}

/// Decrypts packets received from the remote peer.
#[derive(Clone)]
pub struct InboundCipher {
    length_cipher: FSChaCha20,
    packet_cipher: FSChaCha20Poly1305,
}

impl InboundCipher {
    /// Decrypt the length of the packet's payload.
    ///
    /// Note that this returns the length of the remaining packet data
    /// to be read from the stream (header + contents + tag), not just the contents.
    ///
    /// # Arguments
    ///
    /// * `len_bytes` - The first three bytes of the encrypted packet.
    ///
    /// # Returns
    ///
    /// The length of the rest of the packet.
    pub fn decrypt_packet_len(&mut self, mut len_bytes: [u8; NUM_LENGTH_BYTES]) -> usize {
        self.length_cipher.crypt(&mut len_bytes);

        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], 0]) as usize
            + NUM_HEADER_BYTES
            + NUM_TAG_BYTES
    }

    /// Calculate the required decryption buffer length from packet length.
    pub fn decryption_buffer_len(packet_len: usize) -> usize {
        packet_len - NUM_TAG_BYTES
    }

    /// Decrypt an inbound packet in-place.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A mutable buffer containing the packet from the peer excluding
    ///   the first 3 length bytes. It should contain the header, contents, and authentication tag.
    ///   This buffer will be modified in-place during decryption.
    /// * `aad` - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok((PacketType, &[u8]))`: A tuple of the packet type and a slice pointing to the
    ///     decrypted plaintext within the input buffer. The first byte of the slice is the
    ///     header byte containing protocol flags.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    /// * Decryption errors for any failures such as a tag mismatch.
    pub fn decrypt_in_place<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<(PacketType, &'a [u8]), Error> {
        let auth = aad.unwrap_or_default();
        // Check minimum size of ciphertext.
        if ciphertext.len() < NUM_TAG_BYTES + NUM_HEADER_BYTES {
            return Err(Error::CiphertextTooSmall);
        }
        let (msg, tag) = ciphertext.split_at_mut(ciphertext.len() - NUM_TAG_BYTES);

        self.packet_cipher
            .decrypt(auth, msg, tag.try_into().expect("16 byte tag"))?;

        Ok((PacketType::from_byte(&msg[0]), msg))
    }

    /// Decrypt an inbound packet.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///   the header, contents, and authentication tag.
    /// * `plaintext_buffer` - Mutable buffer to write plaintext. Note that the first byte is the header byte
    ///   containing protocol flags.
    /// * `aad` - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(PacketType)`: A flag indicating if the decrypted packet is a decoy or not.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    /// * `BufferTooSmall `    - Contents buffer argument is not large enough for plaintext.
    /// * Decryption errors for any failures such as a tag mismatch.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        plaintext_buffer: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<PacketType, Error> {
        let auth = aad.unwrap_or_default();
        // Check minimum size of ciphertext.
        if ciphertext.len() < NUM_TAG_BYTES + NUM_HEADER_BYTES {
            return Err(Error::CiphertextTooSmall);
        }
        let (msg, tag) = ciphertext.split_at(ciphertext.len() - NUM_TAG_BYTES);
        // Check that the contents buffer is large enough.
        if plaintext_buffer.len() < msg.len() {
            return Err(Error::BufferTooSmall {
                required_bytes: msg.len(),
            });
        }
        plaintext_buffer[0..msg.len()].copy_from_slice(msg);
        self.packet_cipher.decrypt(
            auth,
            &mut plaintext_buffer[0..msg.len()],
            tag.try_into().expect("16 byte tag"),
        )?;

        Ok(PacketType::from_byte(&plaintext_buffer[0]))
    }

    /// Decrypt an inbound packet with automatic allocation.
    ///
    /// This is a convenience method that handles buffer allocation automatically.
    /// For zero-allocation scenarios, use [`decrypt`] instead.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///   the header, contents, and authentication tag.
    /// * `aad` - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok((PacketType, Vec<u8>))`: The packet type and decrypted plaintext including header byte.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    /// * Decryption errors for any failures such as a tag mismatch.
    #[cfg(feature = "std")]
    pub fn decrypt_to_vec(
        &mut self,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(PacketType, std::vec::Vec<u8>), Error> {
        let plaintext_len = Self::decryption_buffer_len(ciphertext.len());
        let mut plaintext_buffer = std::vec![0u8; plaintext_len];

        let packet_type = self.decrypt(ciphertext, &mut plaintext_buffer, aad)?;

        Ok((packet_type, plaintext_buffer))
    }
}

/// Encrypts packets to send to the remote peer.
#[derive(Clone)]
pub struct OutboundCipher {
    length_cipher: FSChaCha20,
    packet_cipher: FSChaCha20Poly1305,
}

impl OutboundCipher {
    /// Calculate the required encryption buffer length for given plaintext length.
    pub const fn encryption_buffer_len(plaintext_len: usize) -> usize {
        plaintext_len + NUM_PACKET_OVERHEAD_BYTES
    }

    /// Encrypt plaintext into a packet for transmission.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext contents to be encrypted.
    /// * `ciphertext_buffer` - Buffer to write packet bytes to which must have enough capacity
    ///   as calculated by `encryption_buffer_len(plaintext.len())`.
    /// * `packet_type` - Is this a genuine packet or a decoy.
    /// * `aad` - Optional associated authenticated data.
    ///
    /// # Errors
    ///
    /// * `Error::BufferTooSmall` - Buffer does not have enough allocated memory as
    ///   calculated by `encryption_buffer_len()`.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext_buffer: &mut [u8],
        packet_type: PacketType,
        aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        // Validate buffer capacity.
        if ciphertext_buffer.len() < Self::encryption_buffer_len(plaintext.len()) {
            return Err(Error::BufferTooSmall {
                required_bytes: Self::encryption_buffer_len(plaintext.len()),
            });
        }

        let plaintext_length = plaintext.len();
        let header_index = NUM_LENGTH_BYTES + NUM_HEADER_BYTES - 1;
        let plaintext_start_index = header_index + 1;
        let plaintext_end_index = plaintext_start_index + plaintext_length;

        // Set header byte.
        ciphertext_buffer[header_index] = packet_type.to_byte();
        ciphertext_buffer[plaintext_start_index..plaintext_end_index].copy_from_slice(plaintext);

        // Encrypt header byte and plaintext in place and produce authentication tag.
        let auth = aad.unwrap_or_default();
        let tag = self.packet_cipher.encrypt(
            auth,
            &mut ciphertext_buffer[header_index..plaintext_end_index],
        );

        // Encrypt plaintext length.
        let mut content_len = [0u8; 3];
        content_len.copy_from_slice(&(plaintext_length as u32).to_le_bytes()[0..NUM_LENGTH_BYTES]);
        self.length_cipher.crypt(&mut content_len);

        // Copy over encrypted length and the tag to the final packet (plaintext already encrypted).
        ciphertext_buffer[0..NUM_LENGTH_BYTES].copy_from_slice(&content_len);
        ciphertext_buffer[plaintext_end_index..(plaintext_end_index + NUM_TAG_BYTES)]
            .copy_from_slice(&tag);

        Ok(())
    }

    /// Encrypt plaintext into a packet with automatic allocation.
    ///
    /// This is a convenience method that handles buffer allocation automatically.
    /// For zero-allocation scenarios, use [`encrypt`] instead.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext contents to be encrypted.
    /// * `packet_type` - Is this a genuine packet or a decoy.
    /// * `aad` - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// The complete encrypted packet ready for transmission.
    #[cfg(feature = "std")]
    pub fn encrypt_to_vec(
        &mut self,
        plaintext: &[u8],
        packet_type: PacketType,
        aad: Option<&[u8]>,
    ) -> std::vec::Vec<u8> {
        let packet_len = Self::encryption_buffer_len(plaintext.len());
        let mut ciphertext_buffer = std::vec![0u8; packet_len];

        // This will never fail since we allocate the exact required size
        self.encrypt(plaintext, &mut ciphertext_buffer, packet_type, aad)
            .expect("encrypt should never fail with correctly sized buffer");

        ciphertext_buffer
    }
}

/// Manages cipher state for a BIP-324 encrypted connection.
#[derive(Clone)]
pub struct CipherSession {
    /// A unique identifier for the communication session.
    id: [u8; 32],
    /// Decrypts inbound packets.
    inbound: InboundCipher,
    /// Encrypts outbound packets.
    outbound: OutboundCipher,
}

impl CipherSession {
    pub(crate) fn new(materials: SessionKeyMaterial, role: Role) -> Self {
        match role {
            Role::Initiator => {
                let initiator_length_cipher = FSChaCha20::new(materials.initiator_length_key);
                let responder_length_cipher = FSChaCha20::new(materials.responder_length_key);
                let initiator_packet_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                let responder_packet_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                CipherSession {
                    id: materials.session_id,
                    inbound: InboundCipher {
                        length_cipher: responder_length_cipher,
                        packet_cipher: responder_packet_cipher,
                    },
                    outbound: OutboundCipher {
                        length_cipher: initiator_length_cipher,
                        packet_cipher: initiator_packet_cipher,
                    },
                }
            }
            Role::Responder => {
                let responder_length_cipher = FSChaCha20::new(materials.responder_length_key);
                let initiator_length_cipher = FSChaCha20::new(materials.initiator_length_key);
                let responder_packet_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                let initiator_packet_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                CipherSession {
                    id: materials.session_id,
                    inbound: InboundCipher {
                        length_cipher: initiator_length_cipher,
                        packet_cipher: initiator_packet_cipher,
                    },
                    outbound: OutboundCipher {
                        length_cipher: responder_length_cipher,
                        packet_cipher: responder_packet_cipher,
                    },
                }
            }
        }
    }

    /// Unique session ID.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get a mutable reference to the inbound cipher for decryption operations.
    pub fn inbound(&mut self) -> &mut InboundCipher {
        &mut self.inbound
    }

    /// Get a mutable reference to the outbound cipher for encryption operations.
    pub fn outbound(&mut self) -> &mut OutboundCipher {
        &mut self.outbound
    }

    /// Split the session into separate inbound and outbound ciphers.
    pub fn into_split(self) -> (InboundCipher, OutboundCipher) {
        (self.inbound, self.outbound)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {

    use super::*;
    use bitcoin::secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
    use bitcoin::secp256k1::SecretKey;
    use core::str::FromStr;
    use hex::prelude::*;
    use rand::Rng;
    use std::vec;
    use std::vec::Vec;

    fn gen_garbage(garbage_len: u32, rng: &mut impl Rng) -> Vec<u8> {
        let buffer: Vec<u8> = (0..garbage_len).map(|_| rng.gen()).collect();
        buffer
    }

    #[test]
    fn test_cipher_session() {
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);
        let message = b"Bitcoin rox!".to_vec();

        let mut enc_packet = vec![0u8; OutboundCipher::encryption_buffer_len(message.len())];
        alice_cipher
            .outbound()
            .encrypt(&message, &mut enc_packet, PacketType::Decoy, None)
            .unwrap();

        let plaintext_len = bob_cipher
            .inbound()
            .decrypt_packet_len(enc_packet[0..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut plaintext_buffer = vec![0u8; InboundCipher::decryption_buffer_len(plaintext_len)];
        let packet_type = bob_cipher
            .inbound()
            .decrypt(&enc_packet[NUM_LENGTH_BYTES..], &mut plaintext_buffer, None)
            .unwrap();
        assert_eq!(PacketType::Decoy, packet_type);
        assert_eq!(message, plaintext_buffer[1..].to_vec()); // Skip header byte

        let message = b"Windows sox!".to_vec();
        let packet_len = OutboundCipher::encryption_buffer_len(message.len());
        let mut enc_packet = vec![0u8; packet_len];
        bob_cipher
            .outbound()
            .encrypt(&message, &mut enc_packet, PacketType::Genuine, None)
            .unwrap();

        let plaintext_len = alice_cipher
            .inbound()
            .decrypt_packet_len(enc_packet[0..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut plaintext_buffer = vec![0u8; InboundCipher::decryption_buffer_len(plaintext_len)];
        let packet_type = alice_cipher
            .inbound()
            .decrypt(&enc_packet[NUM_LENGTH_BYTES..], &mut plaintext_buffer, None)
            .unwrap();
        assert_eq!(PacketType::Genuine, packet_type);
        assert_eq!(message, plaintext_buffer[1..].to_vec()); // Skip header byte
    }

    #[test]
    fn test_decrypt_in_place() {
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);

        // Test with a genuine packet
        let message = b"Test in-place decryption".to_vec();
        let mut enc_packet = vec![0u8; OutboundCipher::encryption_buffer_len(message.len())];
        alice_cipher
            .outbound()
            .encrypt(&message, &mut enc_packet, PacketType::Genuine, None)
            .unwrap();

        // Decrypt in-place
        let mut ciphertext = enc_packet[NUM_LENGTH_BYTES..].to_vec();
        let (packet_type, plaintext) = bob_cipher
            .inbound()
            .decrypt_in_place(&mut ciphertext, None)
            .unwrap();

        assert_eq!(PacketType::Genuine, packet_type);
        assert_eq!(message, plaintext[1..].to_vec()); // Skip header byte

        // Test with a decoy packet and AAD
        let message2 = b"Decoy with AAD".to_vec();
        let aad = b"additional authenticated data";
        let mut enc_packet2 = vec![0u8; OutboundCipher::encryption_buffer_len(message2.len())];
        bob_cipher
            .outbound()
            .encrypt(&message2, &mut enc_packet2, PacketType::Decoy, Some(aad))
            .unwrap();

        // Decrypt in-place with AAD
        let mut ciphertext2 = enc_packet2[NUM_LENGTH_BYTES..].to_vec();
        let (packet_type2, plaintext2) = alice_cipher
            .inbound()
            .decrypt_in_place(&mut ciphertext2, Some(aad))
            .unwrap();

        assert_eq!(PacketType::Decoy, packet_type2);
        assert_eq!(message2, plaintext2[1..].to_vec()); // Skip header byte
    }

    #[test]
    fn test_decrypt_min_length() {
        // Test that decrypt properly validates minimum ciphertext length.
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys, Role::Initiator);

        // Test with ciphertext that is exactly NUM_TAG_BYTES (should fail).
        let too_small = vec![0u8; NUM_TAG_BYTES];
        let mut plaintext_buffer = vec![0u8; 100];
        let result = alice_cipher
            .inbound()
            .decrypt(&too_small, &mut plaintext_buffer, None);
        assert_eq!(result, Err(Error::CiphertextTooSmall));

        // Test decrypt_in_place with same minimum length checks.
        let mut too_small = vec![0u8; NUM_TAG_BYTES];
        let result = alice_cipher
            .inbound()
            .decrypt_in_place(&mut too_small, None);
        assert_eq!(result, Err(Error::CiphertextTooSmall));
    }

    #[test]
    fn test_fuzz_packets() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);
        // Force a rekey under the hood.
        for _ in 0..(224 + 100) {
            let message = gen_garbage(4095, &mut rng);

            let packet_len = OutboundCipher::encryption_buffer_len(message.len());
            let mut enc_packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&message, &mut enc_packet, PacketType::Genuine, None)
                .unwrap();

            let alice_message_len = bob_cipher
                .inbound()
                .decrypt_packet_len(enc_packet[..NUM_LENGTH_BYTES].try_into().unwrap());
            let mut dec_packet = vec![0u8; InboundCipher::decryption_buffer_len(alice_message_len)];
            bob_cipher
                .inbound()
                .decrypt(
                    &enc_packet[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + alice_message_len],
                    &mut dec_packet,
                    None,
                )
                .unwrap();
            assert_eq!(message, dec_packet[1..].to_vec()); // Skip header byte

            let message = gen_garbage(420, &mut rng);
            let packet_len = OutboundCipher::encryption_buffer_len(message.len());
            let mut enc_packet = vec![0u8; packet_len];
            bob_cipher
                .outbound()
                .encrypt(&message, &mut enc_packet, PacketType::Genuine, None)
                .unwrap();

            let bob_message_len = alice_cipher
                .inbound()
                .decrypt_packet_len(enc_packet[..NUM_LENGTH_BYTES].try_into().unwrap());
            let mut dec_packet = vec![0u8; InboundCipher::decryption_buffer_len(bob_message_len)];
            alice_cipher
                .inbound()
                .decrypt(
                    &enc_packet[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + bob_message_len],
                    &mut dec_packet,
                    None,
                )
                .unwrap();
            assert_eq!(message, dec_packet[1..].to_vec()); // Skip header byte
        }
    }

    #[test]
    fn test_additional_authenticated_data() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);
        let auth_garbage = gen_garbage(200, &mut rng);

        let packet_len = OutboundCipher::encryption_buffer_len(VERSION_CONTENT.len());
        let mut enc_packet = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(
                &VERSION_CONTENT,
                &mut enc_packet,
                PacketType::Genuine,
                Some(&auth_garbage),
            )
            .unwrap();

        let alice_message_len = bob_cipher
            .inbound()
            .decrypt_packet_len(enc_packet[..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut plaintext_buffer =
            vec![0u8; InboundCipher::decryption_buffer_len(alice_message_len)];
        let _ = bob_cipher
            .inbound()
            .decrypt(
                &enc_packet[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + alice_message_len],
                &mut plaintext_buffer,
                Some(&auth_garbage),
            )
            .unwrap();
    }

    // The rest are sourced from [the BIP-324 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv).

    #[test]
    fn test_vector_1() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);
        let first = gen_garbage(100, &mut rng);

        let packet_len = OutboundCipher::encryption_buffer_len(first.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&first, &mut enc, PacketType::Genuine, None)
            .unwrap();

        let alice_message_len = bob_cipher
            .inbound()
            .decrypt_packet_len(enc[..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut dec_packet = vec![0u8; InboundCipher::decryption_buffer_len(alice_message_len)];
        bob_cipher
            .inbound()
            .decrypt(
                &enc[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + alice_message_len],
                &mut dec_packet,
                None,
            )
            .unwrap();
        assert_eq!(first, dec_packet[1..].to_vec()); // Skip header byte

        let contents: Vec<u8> = vec![0x8e];
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Genuine, None)
            .unwrap();
        assert_eq!(
            enc,
            Vec::from_hex("7530d2a18720162ac09c25329a60d75adf36eda3c3").unwrap()
        );
    }

    #[test]
    fn test_vector_2() {
        let alice =
            SecretKey::from_str("1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("a1855e10e94e00baa23041d916e259f7044e491da6171269694763f018c7e63693d29575dcb464ac816baa1be353ba12e3876cba7628bd0bd8e755e721eb0140").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_bob,
            elliswift_alice,
            alice,
            ElligatorSwiftParty::B,
            Network::Bitcoin,
        )
        .unwrap();
        let id = session_keys.session_id;
        assert_eq!(
            id.to_vec(),
            Vec::from_hex("9267c54560607de73f18c563b76a2442718879c52dd39852885d4a3c9912c9ea")
                .unwrap()
        );
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Responder);
        let contents: Vec<u8> = Vec::from_hex("3eb1d4e98035cfd8eeb29bac969ed3824a").unwrap();
        for _ in 0..999 {
            let packet_len = OutboundCipher::encryption_buffer_len(0);
            let mut packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&Vec::new(), &mut packet, PacketType::Genuine, None)
                .unwrap();
        }
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Genuine, None)
            .unwrap();
        assert_eq!(
            enc,
            Vec::from_hex(
                "1da1bcf589f9b61872f45b7fa5371dd3f8bdf5d515b0c5f9fe9f0044afb8dc0aa1cd39a8c4"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_vector_3() {
        let alice =
            SecretKey::from_str("0286c41cd30913db0fdff7a64ebda5c8e3e7cef10f2aebc00a7650443cf4c60d")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("d1ee8a93a01130cbf299249a258f94feb5f469e7d0f2f28f69ee5e9aa8f9b54a60f2c3ff2d023634ec7f4127a96cc11662e402894cf1f694fb9a7eaa5f1d9244").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff22d5e441524d571a52b3def126189d3f416890a99d4da6ede2b0cde1760ce2c3f98457ae").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex("054290a6c6ba8d80478172e89d32bf690913ae9835de6dcf206ff1f4d652286fe0ddf74deba41d55de3edc77c42a32af79bbea2c00bae7492264c60866ae5a").unwrap();
        let aad = Vec::from_hex("84932a55aac22b51e7b128d31d9f0550da28e6a3f394224707d878603386b2f9d0c6bcd8046679bfed7b68c517e7431e75d9dd34605727d2ef1c2babbf680ecc8d68d2c4886e9953a4034abde6da4189cd47c6bb3192242cf714d502ca6103ee84e08bc2ca4fd370d5ad4e7d06c7fbf496c6c7cc7eb19c40c61fb33df2a9ba48497a96c98d7b10c1f91098a6b7b16b4bab9687f27585ade1491ae0dba6a79e1e2d85dd9d9d45c5135ca5fca3f0f99a60ea39edbc9efc7923111c937913f225d67788d5f7e8852b697e26b92ec7bfcaa334a1665511c2b4c0a42d06f7ab98a9719516c8fd17f73804555ee84ab3b7d1762f6096b778d3cb9c799cbd49a9e4a325197b4e6cc4a5c4651f8b41ff88a92ec428354531f970263b467c77ed11312e2617d0d53fe9a8707f51f9f57a77bfb49afe3d89d85ec05ee17b9186f360c94ab8bb2926b65ca99dae1d6ee1af96cad09de70b6767e949023e4b380e66669914a741ed0fa420a48dbc7bfae5ef2019af36d1022283dd90655f25eec7151d471265d22a6d3f91dc700ba749bb67c0fe4bc0888593fbaf59d3c6fff1bf756a125910a63b9682b597c20f560ecb99c11a92c8c8c3f7fbfaa103146083a0ccaecf7a5f5e735a784a8820155914a289d57d8141870ffcaf588882332e0bcd8779efa931aa108dab6c3cce76691e345df4a91a03b71074d66333fd3591bff071ea099360f787bbe43b7b3dff2a59c41c7642eb79870222ad1c6f2e5a191ed5acea51134679587c9cf71c7d8ee290be6bf465c4ee47897a125708704ad610d8d00252d01959209d7cd04d5ecbbb1419a7e84037a55fefa13dee464b48a35c96bcb9a53e7ed461c3a1607ee00c3c302fd47cd73fda7493e947c9834a92d63dcfbd65aa7c38c3e3a2748bb5d9a58e7495d243d6b741078c8f7ee9c8813e473a323375702702b0afae1550c8341eedf5247627343a95240cb02e3e17d5dca16f8d8d3b2228e19c06399f8ec5c5e9dbe4caef6a0ea3ffb1d3c7eac03ae030e791fa12e537c80d56b55b764cadf27a8701052df1282ba8b5e3eb62b5dc7973ac40160e00722fa958d95102fc25c549d8c0e84bed95b7acb61ba65700c4de4feebf78d13b9682c52e937d23026fb4c6193e6644e2d3c99f91f4f39a8b9fc6d013f89c3793ef703987954dc0412b550652c01d922f525704d32d70d6d4079bc3551b563fb29577b3aecdc9505011701dddfd94830431e7a4918927ee44fb3831ce8c4513839e2deea1287f3fa1ab9b61a256c09637dbc7b4f0f8fbb783840f9c24526da883b0df0c473cf231656bd7bc1aaba7f321fec0971c8c2c3444bff2f55e1df7fea66ec3e440a612db9aa87bb505163a59e06b96d46f50d8120b92814ac5ab146bc78dbbf91065af26107815678ce6e33812e6bf3285d4ef3b7b04b076f21e7820dcbfdb4ad5218cf4ff6a65812d8fcb98ecc1e95e2fa58e3efe4ce26cd0bd400d6036ab2ad4f6c713082b5e3f1e04eb9e3b6c8f63f57953894b9e220e0130308e1fd91f72d398c1e7962ca2c31be83f31d6157633581a0a6910496de8d55d3d07090b6aa087159e388b7e7dec60f5d8a60d93ca2ae91296bd484d916bfaaa17c8f45ea4b1a91b37c82821199a2b7596672c37156d8701e7352aa48671d3b1bbbd2bd5f0a2268894a25b0cb2514af39c8743f8cce8ab4b523053739fd8a522222a09acf51ac704489cf17e4b7125455cb8f125b4d31af1eba1f8cf7f81a5a100a141a7ee72e8083e065616649c241f233645c5fc865d17f0285f5c52d9f45312c979bfb3ce5f2a1b951deddf280ffb3f370410cffd1583bfa90077835aa201a0712d1dcd1293ee177738b14e6b5e2a496d05220c3253bb6578d6aff774be91946a614dd7e879fb3dcf7451e0b9adb6a8c44f53c2c464bcc0019e9fad89cac7791a0a3f2974f759a9856351d4d2d7c5612c17cfc50f8479945df57716767b120a590f4bf656f4645029a525694d8a238446c5f5c2c1c995c09c1405b8b1eb9e0352ffdf766cc964f8dcf9f8f043dfab6d102cf4b298021abd78f1d9025fa1f8e1d710b38d9d1652f2d88d1305874ec41609b6617b65c5adb19b6295dc5c5da5fdf69f28144ea12f17c3c6fcce6b9b5157b3dfc969d6725fa5b098a4d9b1d31547ed4c9187452d281d0a5d456008caf1aa251fac8f950ca561982dc2dc908d3691ee3b6ad3ae3d22d002577264ca8e49c523bd51c4846be0d198ad9407bf6f7b82c79893eb2c05fe9981f687a97a4f01fe45ff8c8b7ecc551135cd960a0d6001ad35020be07ffb53cb9e731522ca8ae9364628914b9b8e8cc2f37f03393263603cc2b45295767eb0aac29b0930390eb89587ab2779d2e3decb8042acece725ba42eda650863f418f8d0d50d104e44fbbe5aa7389a4a144a8cecf00f45fb14c39112f9bfb56c0acbd44fa3ff261f5ce4acaa5134c2c1d0cca447040820c81ab1bcdc16aa075b7c68b10d06bbb7ce08b5b805e0238f24402cf24a4b4e00701935a0c68add3de090903f9b85b153cb179a582f57113bfc21c2093803f0cfa4d9d4672c2b05a24f7e4c34a8e9101b70303a7378b9c50b6cddd46814ef7fd73ef6923feceab8fc5aa8b0d185f2e83c7a99dcb1077c0ab5c1f5d5f01ba2f0420443f75c4417db9ebf1665efbb33dca224989920a64b44dc26f682cc77b4632c8454d49135e52503da855bc0f6ff8edc1145451a9772c06891f41064036b66c3119a0fc6e80dffeb65dc456108b7ca0296f4175fff3ed2b0f842cd46bd7e86f4c62dfaf1ddbf836263c00b34803de164983d0811cebfac86e7720c726d3048934c36c23189b02386a722ca9f0fe00233ab50db928d3bccea355cc681144b8b7edcaae4884d5a8f04425c0890ae2c74326e138066d8c05f4c82b29df99b034ea727afde590a1f2177ace3af99cfb1729d6539ce7f7f7314b046aab74497e63dd399e1f7d5f16517c23bd830d1fdee810f3c3b77573dd69c4b97d80d71fb5a632e00acdfa4f8e829faf3580d6a72c40b28a82172f8dcd4627663ebf6069736f21735fd84a226f427cd06bb055f94e7c92f31c48075a2955d82a5b9d2d0198ce0d4e131a112570a8ee40fb80462a81436a58e7db4e34b6e2c422e82f934ecda9949893da5730fc5c23c7c920f363f85ab28cc6a4206713c3152669b47efa8238fa826735f17b4e78750276162024ec85458cd5808e06f40dd9fd43775a456a3ff6cae90550d76d8b2899e0762ad9a371482b3e38083b1274708301d6346c22fea9bb4b73db490ff3ab05b2f7f9e187adef139a7794454b7300b8cc64d3ad76c0e4bc54e08833a4419251550655380d675bc91855aeb82585220bb97f03e976579c08f321b5f8f70988d3061f41465517d53ac571dbf1b24b94443d2e9a8e8a79b392b3d6a4ecdd7f626925c365ef6221305105ce9b5f5b6ecc5bed3d702bd4b7f5008aa8eb8c7aa3ade8ecf6251516fbefeea4e1082aa0e1848eddb31ffe44b04792d296054402826e4bd054e671f223e5557e4c94f89ca01c25c44f1a2ff2c05a70b43408250705e1b858bf0670679fdcd379203e36be3500dd981b1a6422c3cf15224f7fefdef0a5f225c5a09d15767598ecd9e262460bb33a4b5d09a64591efabc57c923d3be406979032ae0bc0997b65336a06dd75b253332ad6a8b63ef043f780a1b3fb6d0b6cad98b1ef4a02535eb39e14a866cfc5fc3a9c5deb2261300d71280ebe66a0776a151469551c3c5fa308757f956655278ec6330ae9e3625468c5f87e02cd9a6489910d4143c1f4ee13aa21a6859d907b788e28572fecee273d44e4a900fa0aa668dd861a60fb6b6b12c2c5ef3c8df1bd7ef5d4b0d1cdb8c15fffbb365b9784bd94abd001c6966216b9b67554ad7cb7f958b70092514f7800fc40244003e0fd1133a9b850fb17f4fcafde07fc87b07fb510670654a5d2d6fc9876ac74728ea41593beef003d6858786a52d3a40af7529596767c17000bfaf8dc52e871359f4ad8bf6e7b2853e5229bdf39657e213580294a5317c5df172865e1e17fe37093b585e04613f5f078f761b2b1752eb32983afda24b523af8851df9a02b37e77f543f18888a782a994a50563334282bf9cdfccc183fdf4fcd75ad86ee0d94f91ee2300a5befbccd14e03a77fc031a8cfe4f01e4c5290f5ac1da0d58ea054bd4837cfd93e5e34fc0eb16e48044ba76131f228d16cde9b0bb978ca7cdcd10653c358bdb26fdb723a530232c32ae0a4cecc06082f46e1c1d596bfe60621ad1e354e01e07b040cc7347c016653f44d926d13ca74e6cbc9d4ab4c99f4491c95c76fff5076b3936eb9d0a286b97c035ca88a3c6309f5febfd4cdaac869e4f58ed409b1e9eb4192fb2f9c2f12176d460fd98286c9d6df84598f260119fd29c63f800c07d8df83d5cc95f8c2fea2812e7890e8a0718bb1e031ecbebc0436dcf3e3b9a58bcc06b4c17f711f80fe1dffc3326a6eb6e00283055c6dabe20d311bfd5019591b7954f8163c9afad9ef8390a38f3582e0a79cdf0353de8eeb6b5f9f27b16ffdef7dd62869b4840ee226ccdce95e02c4545eb981b60571cd83f03dc5eaf8c97a0829a4318a9b3dc06c0e003db700b2260ff1fa8fee66890e637b109abb03ec901b05ca599775f48af50154c0e67d82bf0f558d7d3e0778dc38bea1eb5f74dc8d7f90abdf5511a424be66bf8b6a3cacb477d2e7ef4db68d2eba4d5289122d851f9501ba7e9c4957d8eba3be3fc8e785c4265a1d65c46f2809b70846c693864b169c9dcb78be26ea14b8613f145b01887222979a9e67aee5f800caa6f5c4229bdeefc901232ace6143c9865e4d9c07f51aa200afaf7e48a7d1d8faf366023beab12906ffcb3eaf72c0eb68075e4daf3c080e0c31911befc16f0cc4a09908bb7c1e26abab38bd7b788e1a09c0edf1a35a38d2ff1d3ed47fcdaae2f0934224694f5b56705b9409b6d3d64f3833b686f7576ec64bbdd6ff174e56c2d1edac0011f904681a73face26573fbba4e34652f7ae84acfb2fa5a5b3046f98178cd0831df7477de70e06a4c00e305f31aafc026ef064dd68fd3e4252b1b91d617b26c6d09b6891a00df68f105b5962e7f9d82da101dd595d286da721443b72b2aba2377f6e7772e33b3a5e3753da9c2578c5d1daab80187f55518c72a64ee150a7cb5649823c08c9f62cd7d020b45ec2cba8310db1a7785a46ab24785b4d54ff1660b5ca78e05a9a55edba9c60bf044737bc468101c4e8bd1480d749be5024adefca1d998abe33eaeb6b11fbb39da5d905fdd3f611b2e51517ccee4b8af72c2d948573505590d61a6783ab7278fc43fe55b1fcc0e7216444d3c8039bb8145ef1ce01c50e95a3f3feab0aee883fdb94cc13ee4d21c542aa795e18932228981690f4d4c57ca4db6eb5c092e29d8a05139d509a8aeb48baa1eb97a76e597a32b280b5e9d6c36859064c98ff96ef5126130264fa8d2f49213870d9fb036cff95da51f270311d9976208554e48ffd486470d0ecdb4e619ccbd8226147204baf8e235f54d8b1cba8fa34a9a4d055de515cdf180d2bb6739a175183c472e30b5c914d09eeb1b7dafd6872b38b48c6afc146101200e6e6a44fe5684e220adc11f5c403ddb15df8051e6bdef09117a3a5349938513776286473a3cf1d2788bb875052a2e6459fa7926da33380149c7f98d7700528a60c954e6f5ecb65842fde69d614be69eaa2040a4819ae6e756accf936e14c1e894489744a79c1f2c1eb295d13e2d767c09964b61f9cfe497649f712").unwrap();
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut auth = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut auth, PacketType::Genuine, Some(&aad))
            .unwrap();
        let challenge = Vec::from_hex("8da7de6ea7bf2a81a396a42880ba1f5756734c4821309ac9aeffa2a26ce86873b9dc4935a772de6ec5162c6d075b14536800fb174841153511bfb597e992e2fe8a450c4bce102cc550bb37fd564c4d60bf884e").unwrap();
        assert_eq!(auth, challenge);
    }

    #[test]
    fn test_vector_4() {
        let alice =
            SecretKey::from_str("6c77432d1fda31e9f942f8af44607e10f3ad38a65f8a4bddae823e5eff90dc38")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("d2685070c1e6376e633e825296634fd461fa9e5bdf2109bcebd735e5a91f3e587c5cb782abb797fbf6bb5074fd1542a474f2a45b673763ec2db7fb99b737bbb9").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("56bd0c06f10352c3a1a9f4b4c92f6fa2b26df124b57878353c1fc691c51abea77c8817daeeb9fa546b77c8daf79d89b22b0e1b87574ece42371f00237aa9d83a").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_bob,
            elliswift_alice,
            alice,
            ElligatorSwiftParty::B,
            Network::Bitcoin,
        )
        .unwrap();
        let id = session_keys.session_id;
        assert_eq!(
            id.to_vec(),
            Vec::from_hex("7ec02fea8c1484e3d0875f978c5f36d63545e2e4acf56311394422f4b66af612")
                .unwrap()
        );
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Responder);
        let contents: Vec<u8> = Vec::from_hex("7e0e78eb6990b059e6cf0ded66ea93ef82e72aa2f18ac24f2fc6ebab561ae557420729da103f64cecfa20527e15f9fb669a49bbbf274ef0389b3e43c8c44e5f60bf2ac38e2b55e7ec4273dba15ba41d21f8f5b3ee1688b3c29951218caf847a97fb50d75a86515d445699497d968164bf740012679b8962de573be941c62b7ef").unwrap();
        for _ in 0..223 {
            let packet_len = OutboundCipher::encryption_buffer_len(0);
            let mut packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&Vec::new(), &mut packet, PacketType::Decoy, None)
                .unwrap();
        }
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Decoy, None)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("729847a3e9eba7a5bff454b5de3b393431ee360736b6c030d7a5bd01d1203d2e98f528543fd2bf886ccaa1ada5e215a730a36b3f4abfc4e252c89eb01d9512f94916dae8a76bf16e4da28986ffe159090fe5267ee3394300b7ccf4dfad389a26321b3a3423e4594a82ccfbad16d6561ecb8772b0cb040280ff999a29e3d9d4fd"),
        );
    }

    #[test]
    fn test_vector_5() {
        let alice =
            SecretKey::from_str("a6ec25127ca1aa4cf16b20084ba1e6516baae4d32422288e9b36d8bddd2de35a")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff053d7ecca53e33e185a8b9be4e7699a97c6ff4c795522e5918ab7cd6b6884f67e683f3dc").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7730be30000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex("00cf68f8f7ac49ffaa02c4864fdf6dfe7bbf2c740b88d98c50ebafe32c92f3427f57601ffcb21a3435979287db8fee6c302926741f9d5e464c647eeb9b7acaeda46e00abd7506fc9a719847e9a7328215801e96198dac141a15c7c2f68e0690dd1176292a0dded04d1f548aad88f1aebdc0a8f87da4bb22df32dd7c160c225b843e83f6525d6d484f502f16d923124fc538794e21da2eb689d18d87406ecced5b9f92137239ed1d37bcfa7836641a83cf5e0a1cf63f51b06f158e499a459ede41c").unwrap();
        for _ in 0..448 {
            let packet_len = OutboundCipher::encryption_buffer_len(0);
            let mut packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&Vec::new(), &mut packet, PacketType::Genuine, None)
                .unwrap();
        }
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Genuine, None)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("77b4656934a82de1a593d8481f020194ddafd8cac441f9d72aeb8721e6a14f49698ca6d9b2b6d59d07a01aa552fd4d5b68d0d1617574c77dea10bfadbaa31b83885b7ceac2fd45e3e4a331c51a74e7b1698d81b64c87c73c5b9258b4d83297f9debc2e9aa07f8572ff434dc792b83ecf07b3197de8dc9cf7be56acb59c66cff5"),
        );
    }

    #[test]
    fn test_vector_6() {
        let alice =
            SecretKey::from_str("0af952659ed76f80f585966b95ab6e6fd68654672827878684c8b547b1b94f5a")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc81017fd92fd31637c26c906b42092e11cc0d3afae8d9019d2578af22735ce7bc469c72d").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("9652d78baefc028cd37a6a92625b8b8f85fde1e4c944ad3f20e198bef8c02f19fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2e91870").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_bob,
            elliswift_alice,
            alice,
            ElligatorSwiftParty::B,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Responder);
        let contents = Vec::from_hex(
            "5c6272ee55da855bbbf7b1246d9885aa7aa601a715ab86fa46c50da533badf82b97597c968293ae04e"
                .repeat(97561)
                .as_str(),
        )
        .unwrap();
        for _ in 0..673 {
            let packet_len = OutboundCipher::encryption_buffer_len(0);
            let mut packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&Vec::new(), &mut packet, PacketType::Genuine, None)
                .unwrap();
        }
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Genuine, None)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("657a4a19711ce593c3844cb391b224f60124aba7e04266233bc50cafb971e26c7716b76e98376448f7d214dd11e629ef9a974d60e3770a695810a61c4ba66d78b936ee7892b98f0b48ddae9fcd8b599dca1c9b43e9b95e0226cf8d4459b8a7c2c4e6db80f1d58c7b20dd7208fa5c1057fb78734223ee801dbd851db601fee61e"),
        );
    }

    #[test]
    fn test_vector_7() {
        let alice =
            SecretKey::from_str("f90e080c64b05824c5a24b2501d5aeaf08af3872ee860aa80bdcd430f7b63494")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff115173765dc202cf029ad3f15479735d57697af12b0131dd21430d5772e4ef11474d58b9").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("12a50f3fafea7c1eeada4cf8d33777704b77361453afc83bda91eef349ae044d20126c6200547ea5a6911776c05dee2a7f1a9ba7dfbabbbd273c3ef29ef46e46").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex(
            "5f67d15d22ca9b2804eeab0a66f7f8e3a10fa5de5809a046084348cbc5304e843ef96f59a59c7d7fdfe5946489f3ea297d941bac326225df316a25fc90f0e65b0d31a9c497e960fdbf8c482516bc8a9c1c77b7f6d0e1143810c737f76f9224e6f2c9af5186b4f7259c7e8d165b6e4fe3d38a60bdbdd4d06ecdcaaf62086070dbb68686b802d53dfd7db14b18743832605f5461ad81e2af4b7e8ff0eff0867a25b93cec7becf15c43131895fed09a83bf1ee4a87d44dd0f02a837bf5a1232e201cb882734eb9643dc2dc4d4e8b5690840766212c7ac8f38ad8a9ec47c7a9b3e022ae3eb6a32522128b518bd0d0085dd81c5"
                .repeat(69615)
                .as_str(),
        )
        .unwrap();
        for _ in 0..1024 {
            let packet_len = OutboundCipher::encryption_buffer_len(0);
            let mut packet = vec![0u8; packet_len];
            alice_cipher
                .outbound()
                .encrypt(&Vec::new(), &mut packet, PacketType::Genuine, None)
                .unwrap();
        }
        let packet_len = OutboundCipher::encryption_buffer_len(contents.len());
        let mut enc = vec![0u8; packet_len];
        alice_cipher
            .outbound()
            .encrypt(&contents, &mut enc, PacketType::Decoy, None)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("7c4b9e1e6c1ce69da7b01513cdc4588fd93b04dafefaf87f31561763d906c672bac3dfceb751ebd126728ac017d4d580e931b8e5c7d5dfe0123be4dc9b2d2238b655c8a7fadaf8082c31e310909b5b731efc12f0a56e849eae6bfeedcc86dd27ef9b91d159256aa8e8d2b71a311f73350863d70f18d0d7302cf551e4303c7733"),
        );
    }
}
