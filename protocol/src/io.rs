// SPDX-License-Identifier: CC0-1.0

//! High-level interfaces for establishing and using BIP324 encrypted
//! connections over Read/Write transports.

use core::fmt;
use std::vec;
use std::vec::Vec;

use bitcoin::Network;

use crate::{
    handshake::{self, GarbageResult, VersionResult},
    Error, Handshake, InboundCipher, OutboundCipher, PacketType, Role, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_GARBAGE_TERMINTOR_BYTES,
};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A decrypted BIP324 payload with its packet type.
pub struct Payload {
    contents: Vec<u8>,
    packet_type: PacketType,
}

impl Payload {
    /// Create a new payload.
    pub fn new(contents: Vec<u8>, packet_type: PacketType) -> Self {
        Self {
            contents,
            packet_type,
        }
    }

    /// Access the decrypted payload contents.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    /// Access the packet type.
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }
}

/// High level error type for the protocol interface.
#[derive(Debug)]
pub enum ProtocolError {
    /// Wrap all IO errors with suggestion for next step on failure.
    Io(std::io::Error, ProtocolFailureSuggestion),
    /// Internal protocol specific errors.
    Internal(Error),
}

/// Suggest to caller next step on protocol failure.
#[derive(Debug)]
pub enum ProtocolFailureSuggestion {
    /// Caller could attempt to retry the connection with protocol V1 if desired.
    RetryV1,
    /// Caller should not attempt to retry connection.
    Abort,
}

impl From<std::io::Error> for ProtocolError {
    fn from(error: std::io::Error) -> Self {
        // Detect IO errors which possibly mean the remote doesn't understand
        // the V2 protocol and immediately closed the connection.
        let suggestion = match error.kind() {
            // The remote force closed the connection.
            std::io::ErrorKind::ConnectionReset
            // A more general error than ConnectionReset, but could be caused
            // by the remote closing the connection.
            | std::io::ErrorKind::ConnectionAborted
            // End of file read errors can occur if the remote closes the connection,
            // but the local system reads due to timing issues.
            | std::io::ErrorKind::UnexpectedEof => ProtocolFailureSuggestion::RetryV1,
            _ => ProtocolFailureSuggestion::Abort,
        };

        ProtocolError::Io(error, suggestion)
    }
}

impl From<Error> for ProtocolError {
    fn from(error: Error) -> Self {
        ProtocolError::Internal(error)
    }
}

impl ProtocolError {
    /// Create an EOF error that suggests retrying with V1 protocol.
    ///
    /// This is used when the remote peer closes the connection during handshake,
    /// which often indicates they don't support the V2 protocol.
    fn eof() -> Self {
        ProtocolError::Io(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Remote peer closed connection during handshake",
            ),
            ProtocolFailureSuggestion::RetryV1,
        )
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Io(e, _) => Some(e),
            ProtocolError::Internal(e) => Some(e),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Io(e, suggestion) => {
                write!(
                    f,
                    "IO error: {}. Suggestion: {}.",
                    e,
                    match suggestion {
                        ProtocolFailureSuggestion::RetryV1 => "Retry with V1 protocol",
                        ProtocolFailureSuggestion::Abort => "Abort, do not retry",
                    }
                )
            }
            ProtocolError::Internal(e) => write!(f, "Internal error: {e}."),
        }
    }
}

/// A protocol session with handshake and send/receive packet management.
#[cfg(feature = "tokio")]
pub struct AsyncProtocol {
    reader: AsyncProtocolReader,
    writer: AsyncProtocolWriter,
}

#[cfg(feature = "tokio")]
impl AsyncProtocol {
    /// New protocol session which completes the initial handshake and returns a handler.
    ///
    /// This function is *not* cancellation safe.
    ///
    /// # Arguments
    ///
    /// * `network` - Network which both parties are operating on.
    /// * `role` - Role in handshake, initiator or responder.
    /// * `garbage` - Optional garbage bytes to send in handshake.
    /// * `decoys` - Optional decoy packet contents bytes to send in handshake.
    /// * `reader` - Asynchronous buffer to read packets sent by peer.
    /// * `writer` - Asynchronous buffer to write packets to peer.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(AsyncProtocol)`: An initialized protocol handler.
    ///   * `Err(ProtocolError)`: An error that occurred during the handshake.
    ///
    /// # Errors
    ///
    /// * `Io` - Includes a flag for if the remote probably only understands the V1 protocol.
    pub async fn new<'a, R, W>(
        network: Network,
        role: Role,
        garbage: Option<&'a [u8]>,
        decoys: Option<&'a [&'a [u8]]>,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let handshake = Handshake::<handshake::Initialized>::new(network, role)?;

        // Send local public key and optional garbage.
        let key_buffer_len = Handshake::<handshake::Initialized>::send_key_len(garbage);
        let mut key_buffer = vec![0u8; key_buffer_len];
        let handshake = handshake.send_key(garbage, &mut key_buffer)?;
        writer.write_all(&key_buffer).await?;
        writer.flush().await?;

        // Read remote's public key.
        let mut remote_ellswift_buffer = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        reader.read_exact(&mut remote_ellswift_buffer).await?;
        let handshake = handshake.receive_key(remote_ellswift_buffer)?;

        // Send garbage terminator, decoys, and version.
        let version_buffer_len = Handshake::<handshake::ReceivedKey>::send_version_len(decoys);
        let mut version_buffer = vec![0u8; version_buffer_len];
        let handshake = handshake.send_version(&mut version_buffer, decoys)?;
        writer.write_all(&version_buffer).await?;
        writer.flush().await?;

        // Receive and process garbage terminator
        let mut garbage_buffer = vec![0u8; NUM_GARBAGE_TERMINTOR_BYTES];
        reader.read_exact(&mut garbage_buffer).await?;

        let mut handshake = handshake;
        let (mut handshake, garbage_bytes) = loop {
            match handshake.receive_garbage(&garbage_buffer) {
                Ok(GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                }) => {
                    break (handshake, consumed_bytes);
                }
                Ok(GarbageResult::NeedMoreData(h)) => {
                    handshake = h;
                    // Use small chunks to avoid reading past garbage, decoys, and version.
                    let mut temp = vec![0u8; NUM_GARBAGE_TERMINTOR_BYTES];
                    match reader.read(&mut temp).await {
                        Ok(0) => return Err(ProtocolError::eof()),
                        Ok(n) => {
                            garbage_buffer.extend_from_slice(&temp[..n]);
                        }
                        Err(e) => return Err(ProtocolError::from(e)),
                    }
                }
                Err(e) => return Err(ProtocolError::Internal(e)),
            }
        };

        // Process remaining bytes and read version packets.
        let mut version_buffer = garbage_buffer[garbage_bytes..].to_vec();
        loop {
            // Decrypt packet length.
            if version_buffer.len() < 3 {
                let old_len = version_buffer.len();
                version_buffer.resize(3, 0);
                reader.read_exact(&mut version_buffer[old_len..]).await?;
            }
            let packet_len =
                handshake.decrypt_packet_len(version_buffer[..3].try_into().unwrap())?;
            version_buffer.drain(..3);

            // Process packet.
            if version_buffer.len() < packet_len {
                let old_len = version_buffer.len();
                version_buffer.resize(packet_len, 0);
                reader.read_exact(&mut version_buffer[old_len..]).await?;
            }
            match handshake.receive_version(&mut version_buffer) {
                Ok(VersionResult::Complete { cipher }) => {
                    let (inbound_cipher, outbound_cipher) = cipher.into_split();
                    return Ok(Self {
                        reader: AsyncProtocolReader {
                            inbound_cipher,
                            state: DecryptState::init_reading_length(),
                        },
                        writer: AsyncProtocolWriter { outbound_cipher },
                    });
                }
                Ok(VersionResult::Decoy(h)) => {
                    handshake = h;
                    version_buffer.drain(..packet_len);
                }
                Err(e) => return Err(ProtocolError::Internal(e)),
            }
        }
    }

    /// Read reference for packet reading operations.
    pub fn reader(&mut self) -> &mut AsyncProtocolReader {
        &mut self.reader
    }

    /// Write reference for packet writing operations.
    pub fn writer(&mut self) -> &mut AsyncProtocolWriter {
        &mut self.writer
    }

    /// Split the protocol into a separate reader and writer.
    pub fn into_split(self) -> (AsyncProtocolReader, AsyncProtocolWriter) {
        (self.reader, self.writer)
    }
}

/// State machine of an asynchronous packet read.
///
/// This maintains state between await points to ensure cancellation safety.
#[cfg(feature = "tokio")]
#[derive(Debug)]
enum DecryptState {
    ReadingLength {
        length_bytes: [u8; 3],
        bytes_read: usize,
    },
    ReadingPayload {
        packet_bytes: Vec<u8>,
        bytes_read: usize,
    },
}

#[cfg(feature = "tokio")]
impl DecryptState {
    /// Transition state to reading the length bytes.
    fn init_reading_length() -> Self {
        DecryptState::ReadingLength {
            length_bytes: [0u8; 3],
            bytes_read: 0,
        }
    }

    /// Transition state to reading payload bytes.
    fn init_reading_payload(packet_bytes_len: usize) -> Self {
        DecryptState::ReadingPayload {
            packet_bytes: vec![0u8; packet_bytes_len],
            bytes_read: 0,
        }
    }
}

/// Manages an async buffer to automatically decrypt contents of received packets.
#[cfg(feature = "tokio")]
pub struct AsyncProtocolReader {
    inbound_cipher: InboundCipher,
    state: DecryptState,
}

#[cfg(feature = "tokio")]
impl AsyncProtocolReader {
    /// Decrypt contents of received packet from buffer.
    ///
    /// This function is cancellation safe.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Asynchronous I/O buffer to pull bytes from.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Payload)`: A decrypted payload with packet type.
    ///   * `Err(ProtocolError)`: An error that occurred during the read or decryption.
    pub async fn read_and_decrypt<R>(&mut self, buffer: &mut R) -> Result<Payload, ProtocolError>
    where
        R: AsyncRead + Unpin + Send,
    {
        // Storing state between async reads to make function cancellation safe.
        loop {
            match &mut self.state {
                DecryptState::ReadingLength {
                    length_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < 3 {
                        *bytes_read += buffer.read(&mut length_bytes[*bytes_read..]).await?;
                    }

                    let packet_bytes_len = self.inbound_cipher.decrypt_packet_len(*length_bytes);
                    self.state = DecryptState::init_reading_payload(packet_bytes_len);
                }
                DecryptState::ReadingPayload {
                    packet_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < packet_bytes.len() {
                        *bytes_read += buffer.read(&mut packet_bytes[*bytes_read..]).await?;
                    }

                    let plaintext_len = InboundCipher::decryption_buffer_len(packet_bytes.len());
                    let mut plaintext_buffer = vec![0u8; plaintext_len];
                    let packet_type =
                        self.inbound_cipher
                            .decrypt(packet_bytes, &mut plaintext_buffer, None)?;
                    self.state = DecryptState::init_reading_length();
                    // Skip the header byte (first byte) which contains the packet type
                    return Ok(Payload::new(plaintext_buffer[1..].to_vec(), packet_type));
                }
            }
        }
    }

    /// Consume the protocol reader in exchange for the underlying inbound cipher.
    pub fn into_cipher(self) -> InboundCipher {
        self.inbound_cipher
    }
}

/// Manages an async buffer to automatically encrypt and send contents in packets.
#[cfg(feature = "tokio")]
pub struct AsyncProtocolWriter {
    outbound_cipher: OutboundCipher,
}

#[cfg(feature = "tokio")]
impl AsyncProtocolWriter {
    /// Encrypt contents and write packet buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Asynchronous I/O buffer to write bytes to.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok()`: On successful contents encryption and packet send.
    ///   * `Err(ProtocolError)`: An error that occurred during the encryption or write.
    pub async fn encrypt_and_write<W>(
        &mut self,
        plaintext: &[u8],
        buffer: &mut W,
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let packet_len = OutboundCipher::encryption_buffer_len(plaintext.len());
        let mut packet_buffer = vec![0u8; packet_len];

        self.outbound_cipher
            .encrypt(plaintext, &mut packet_buffer, PacketType::Genuine, None)?;

        buffer.write_all(&packet_buffer).await?;
        buffer.flush().await?;
        Ok(())
    }

    /// Consume the protocol writer in exchange for the underlying outbound cipher.
    pub fn into_cipher(self) -> OutboundCipher {
        self.outbound_cipher
    }
}
