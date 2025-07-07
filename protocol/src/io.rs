// SPDX-License-Identifier: CC0-1.0

//! High-level interfaces for establishing and using BIP-324 encrypted
//! connections over Read/Write transports.

use core::fmt;
use std::io::{Chain, Cursor, Read, Write};
use std::vec;
use std::vec::Vec;

use bitcoin::Network;

use crate::{
    handshake::{self, GarbageResult, VersionResult},
    Error, Handshake, InboundCipher, OutboundCipher, PacketType, Role, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_GARBAGE_TERMINTOR_BYTES, NUM_LENGTH_BYTES,
};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A decrypted BIP-324 payload.
pub struct Payload {
    data: Vec<u8>,
}

impl Payload {
    /// Create a new payload from complete decrypted data (including header byte).
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Access just the message contents (excluding header byte).
    pub fn contents(&self) -> &[u8] {
        &self.data[1..]
    }

    /// Extract the packet type from the header byte.
    pub fn packet_type(&self) -> PacketType {
        PacketType::from_byte(&self.data[0])
    }
}

/// A reader for BIP-324 session data that handles any buffered handshake overflow.
///
/// This reader ensures seamless transition from handshake to session data by
/// first consuming any data that was read during handshake but belongs to the
/// session stream.
pub struct SessionReader<R> {
    inner: Chain<Cursor<Vec<u8>>, R>,
}

impl<R: Read> SessionReader<R> {
    fn new(buffer: Vec<u8>, reader: R) -> Self {
        Self {
            inner: std::io::Read::chain(Cursor::new(buffer), reader),
        }
    }
}

impl<R: Read> Read for SessionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
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
            if version_buffer.len() < NUM_LENGTH_BYTES {
                let old_len = version_buffer.len();
                version_buffer.resize(NUM_LENGTH_BYTES, 0);
                reader.read_exact(&mut version_buffer[old_len..]).await?;
            }
            let packet_len = handshake
                .decrypt_packet_len(version_buffer[..NUM_LENGTH_BYTES].try_into().unwrap())?;
            version_buffer.drain(..NUM_LENGTH_BYTES);

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
        length_bytes: [u8; NUM_LENGTH_BYTES],
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
            length_bytes: [0u8; NUM_LENGTH_BYTES],
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
                    while *bytes_read < NUM_LENGTH_BYTES {
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
                    self.inbound_cipher
                        .decrypt(packet_bytes, &mut plaintext_buffer, None)?;
                    self.state = DecryptState::init_reading_length();
                    return Ok(Payload::new(plaintext_buffer));
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

/// Perform a BIP-324 handshake and return ready-to-use session components.
///
/// This function handles the complete handshake process and returns the
/// cryptographic ciphers and a session reader prepared for encrypted communication.
///
/// # Arguments
///
/// * `network` - Network which both parties are operating on.
/// * `role` - Role in handshake, initiator or responder.
/// * `garbage` - Optional garbage bytes to send in handshake.
/// * `decoys` - Optional decoy packet contents bytes to send in handshake.
/// * `reader` - Buffer to read packets sent by peer (takes ownership).
/// * `writer` - Buffer to write packets to peer (takes mutable reference).
///
/// # Reader Transformation
///
/// The I/O reader is transformed in order to handle possible over-read
/// scenarios while attempting to detect the remote's garbage terminator.
///
/// # Returns
///
/// A `Result` containing:
///   * `Ok((InboundCipher, OutboundCipher, SessionReader<R>))`: Ready-to-use session components.
///   * `Err(ProtocolError)`: An error that occurred during the handshake.
///
/// # Errors
///
/// * `Io` - Includes a flag for if the remote probably only understands the V1 protocol.
pub fn handshake<R, W>(
    network: Network,
    role: Role,
    garbage: Option<&[u8]>,
    decoys: Option<&[&[u8]]>,
    reader: R,
    writer: &mut W,
) -> Result<(InboundCipher, OutboundCipher, SessionReader<R>), ProtocolError>
where
    R: Read,
    W: Write,
{
    let handshake = Handshake::<handshake::Initialized>::new(network, role)?;
    handshake_with_initialized(handshake, garbage, decoys, reader, writer)
}

/// Internal handshake implementation that accepts an already-initialized handshake.
///
/// This allows for testing with deterministic handshake states.
fn handshake_with_initialized<R, W>(
    handshake: Handshake<handshake::Initialized>,
    garbage: Option<&[u8]>,
    decoys: Option<&[&[u8]]>,
    mut reader: R,
    writer: &mut W,
) -> Result<(InboundCipher, OutboundCipher, SessionReader<R>), ProtocolError>
where
    R: Read,
    W: Write,
{
    // Send local public key and optional garbage.
    let key_buffer_len = Handshake::<handshake::Initialized>::send_key_len(garbage);
    let mut key_buffer = vec![0u8; key_buffer_len];
    let handshake = handshake.send_key(garbage, &mut key_buffer)?;
    writer.write_all(&key_buffer)?;
    writer.flush()?;

    // Read remote's public key.
    let mut remote_ellswift_buffer = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
    reader.read_exact(&mut remote_ellswift_buffer)?;
    let handshake = handshake.receive_key(remote_ellswift_buffer)?;

    // Send garbage terminator, decoys, and version.
    let version_buffer_len = Handshake::<handshake::ReceivedKey>::send_version_len(decoys);
    let mut version_buffer = vec![0u8; version_buffer_len];
    let handshake = handshake.send_version(&mut version_buffer, decoys)?;
    writer.write_all(&version_buffer)?;
    writer.flush()?;

    // Receive and process garbage terminator
    let mut garbage_buffer = vec![0u8; NUM_GARBAGE_TERMINTOR_BYTES];
    reader.read_exact(&mut garbage_buffer)?;

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
                // The 256 bytes is a bit arbitrary. There is a max of 4095, but not sure
                // all of that should be allocated right away.
                let mut temp = vec![0u8; 256];
                match reader.read(&mut temp) {
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

    // Process remaining bytes for decoy packets and version.
    let mut session_reader = SessionReader::new(garbage_buffer[garbage_bytes..].to_vec(), reader);
    loop {
        // Decrypt packet length.
        let mut length_bytes = [0u8; NUM_LENGTH_BYTES];
        session_reader.read_exact(&mut length_bytes)?;
        let packet_len = handshake.decrypt_packet_len(length_bytes)?;

        // Process packet.
        let mut packet_bytes = vec![0u8; packet_len];
        session_reader.read_exact(&mut packet_bytes)?;
        match handshake.receive_version(&mut packet_bytes) {
            Ok(VersionResult::Complete { cipher }) => {
                let (inbound_cipher, outbound_cipher) = cipher.into_split();
                return Ok((inbound_cipher, outbound_cipher, session_reader));
            }
            Ok(VersionResult::Decoy(h)) => {
                handshake = h;
            }
            Err(e) => return Err(ProtocolError::Internal(e)),
        }
    }
}

/// A synchronous protocol session with handshake and send/receive packet management.
pub struct Protocol<R, W> {
    reader: ProtocolReader<SessionReader<R>>,
    writer: ProtocolWriter<W>,
}

impl<R, W> Protocol<R, W>
where
    R: Read,
    W: Write,
{
    /// New protocol session which completes the initial handshake and returns a handler.
    ///
    /// # Arguments
    ///
    /// * `network` - Network which both parties are operating on.
    /// * `role` - Role in handshake, initiator or responder.
    /// * `garbage` - Optional garbage bytes to send in handshake.
    /// * `decoys` - Optional decoy packet contents bytes to send in handshake.
    /// * `reader` - Buffer to read packets sent by peer (takes ownership).
    /// * `writer` - Buffer to write packets to peer (takes ownership).
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Protocol)`: An initialized protocol handler.
    ///   * `Err(ProtocolError)`: An error that occurred during the handshake.
    ///
    /// # Errors
    ///
    /// * `Io` - Includes a flag for if the remote probably only understands the V1 protocol.
    pub fn new<'a>(
        network: Network,
        role: Role,
        garbage: Option<&'a [u8]>,
        decoys: Option<&'a [&'a [u8]]>,
        reader: R,
        mut writer: W,
    ) -> Result<Self, ProtocolError> {
        let (inbound_cipher, outbound_cipher, session_reader) =
            handshake(network, role, garbage, decoys, reader, &mut writer)?;

        Ok(Self {
            reader: ProtocolReader {
                inbound_cipher,
                reader: session_reader,
            },
            writer: ProtocolWriter {
                outbound_cipher,
                writer,
            },
        })
    }

    /// Split the protocol into a separate reader and writer.
    pub fn into_split(self) -> (ProtocolReader<SessionReader<R>>, ProtocolWriter<W>) {
        (self.reader, self.writer)
    }

    /// Read and decrypt a packet from the underlying reader.
    ///
    /// This is a convenience method that calls read on the internal reader.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Payload)`: A decrypted payload with packet type.
    ///   * `Err(ProtocolError)`: An error that occurred during the read or decryption.
    pub fn read(&mut self) -> Result<Payload, ProtocolError> {
        self.reader.read()
    }

    /// Encrypt and write a packet to the underlying writer.
    ///
    /// This is a convenience method that calls write on the internal writer.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt and send.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok()`: On successful contents encryption and packet send.
    ///   * `Err(ProtocolError)`: An error that occurred during the encryption or write.
    pub fn write(&mut self, plaintext: &[u8]) -> Result<(), ProtocolError> {
        self.writer.write(plaintext)
    }
}

/// Manages a buffer to automatically decrypt contents of received packets.
pub struct ProtocolReader<R> {
    inbound_cipher: InboundCipher,
    reader: R,
}

impl<R> ProtocolReader<R>
where
    R: Read,
{
    /// Decrypt contents of received packet from the internal reader.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Payload)`: A decrypted payload with packet type.
    ///   * `Err(ProtocolError)`: An error that occurred during the read or decryption.
    pub fn read(&mut self) -> Result<Payload, ProtocolError> {
        // Read packet length.
        let mut length_bytes = [0u8; NUM_LENGTH_BYTES];
        self.reader.read_exact(&mut length_bytes)?;
        let packet_bytes_len = self.inbound_cipher.decrypt_packet_len(length_bytes);

        // Read packet data.
        let mut packet_bytes = vec![0u8; packet_bytes_len];
        self.reader.read_exact(&mut packet_bytes)?;
        let (_, plaintext_buffer) = self.inbound_cipher.decrypt_to_vec(&packet_bytes, None)?;

        Ok(Payload::new(plaintext_buffer))
    }

    /// Consume the protocol reader in exchange for the underlying reader and cipher.
    pub fn into_inner(self) -> (InboundCipher, R) {
        (self.inbound_cipher, self.reader)
    }
}

/// Manages a buffer to automatically encrypt and send contents in packets.
pub struct ProtocolWriter<W> {
    outbound_cipher: OutboundCipher,
    writer: W,
}

impl<W> ProtocolWriter<W>
where
    W: Write,
{
    /// Encrypt contents and write packet to the internal writer.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt and send.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok()`: On successful contents encryption and packet send.
    ///   * `Err(ProtocolError)`: An error that occurred during the encryption or write.
    pub fn write(&mut self, plaintext: &[u8]) -> Result<(), ProtocolError> {
        let packet_buffer =
            self.outbound_cipher
                .encrypt_to_vec(plaintext, PacketType::Genuine, None);
        self.writer.write_all(&packet_buffer)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Consume the protocol writer in exchange for the underlying writer and cipher.
    pub fn into_inner(self) -> (OutboundCipher, W) {
        (self.outbound_cipher, self.writer)
    }
}

/// Extension trait to convert duplex streams into BIP-324 Protocol instances.
///
/// # Example
///
/// ```rust
/// use std::net::TcpStream;
/// use bip324::io::IntoBip324;
/// use bip324::{Network, Role};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let stream = TcpStream::connect("127.0.0.1:8333")?;
/// let protocol = stream.into_bip324(
///     Network::Bitcoin,
///     Role::Initiator,
///     None, // no garbage
///     None, // no decoys
/// )?;
/// # Ok(())
/// # }
/// ```
pub trait IntoBip324<S> {
    /// Convert this stream into a BIP-324 Protocol after performing the handshake.
    ///
    /// # Arguments
    ///
    /// * `network` - Network which both parties are operating on.
    /// * `role` - Role in handshake, initiator or responder.
    /// * `garbage` - Optional garbage bytes to send in handshake.
    /// * `decoys` - Optional decoy packet contents bytes to send in handshake.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Protocol)`: An initialized protocol handler.
    ///   * `Err(ProtocolError)`: An error that occurred during the handshake or stream cloning.
    ///
    /// # Errors
    ///
    /// * `Io` - Includes errors from stream cloning and handshake I/O operations.
    /// * `Internal` - Protocol-specific errors during handshake.
    fn into_bip324(
        self,
        network: Network,
        role: Role,
        garbage: Option<&[u8]>,
        decoys: Option<&[&[u8]]>,
    ) -> Result<Protocol<S, S>, ProtocolError>;
}

impl IntoBip324<std::net::TcpStream> for std::net::TcpStream {
    fn into_bip324(
        self,
        network: Network,
        role: Role,
        garbage: Option<&[u8]>,
        decoys: Option<&[&[u8]]>,
    ) -> Result<Protocol<std::net::TcpStream, std::net::TcpStream>, ProtocolError> {
        let reader = self.try_clone()?;
        let writer = self;
        Protocol::new(network, role, garbage, decoys, reader, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::io::Cursor;

    /// Generate deterministic handshake messages for testing.
    /// Returns the complete handshake message (key + garbage + version) for the specified role.
    fn generate_handshake_messages(
        local_seed: u64,
        remote_seed: u64,
        role: Role,
        garbage: Option<&[u8]>,
        decoys: Option<&[&[u8]]>,
    ) -> Vec<u8> {
        let secp = bitcoin::secp256k1::Secp256k1::new();

        // Create both parties.
        let mut local_rng = StdRng::seed_from_u64(local_seed);
        let local_handshake = Handshake::<handshake::Initialized>::new_with_rng(
            Network::Bitcoin,
            role,
            &mut local_rng,
            &secp,
        )
        .unwrap();

        let mut remote_rng = StdRng::seed_from_u64(remote_seed);
        let remote_role = match role {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        };
        let remote_handshake = Handshake::<handshake::Initialized>::new_with_rng(
            Network::Bitcoin,
            remote_role,
            &mut remote_rng,
            &secp,
        )
        .unwrap();

        // Exchange keys.
        let mut local_key_buffer =
            vec![0u8; Handshake::<handshake::Initialized>::send_key_len(garbage)];
        let local_handshake = local_handshake
            .send_key(garbage, &mut local_key_buffer)
            .unwrap();

        let mut remote_key_buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        remote_handshake
            .send_key(None, &mut remote_key_buffer)
            .unwrap();

        let local_handshake = local_handshake
            .receive_key(
                remote_key_buffer[..NUM_ELLIGATOR_SWIFT_BYTES]
                    .try_into()
                    .unwrap(),
            )
            .unwrap();

        let mut local_version_buffer =
            vec![0u8; Handshake::<handshake::ReceivedKey>::send_version_len(decoys)];
        local_handshake
            .send_version(&mut local_version_buffer, decoys)
            .unwrap();

        // Return complete message: key + garbage + version.
        let garbage_bytes = garbage.map(|g| g.to_vec()).unwrap_or_default();
        [
            &local_key_buffer[..NUM_ELLIGATOR_SWIFT_BYTES],
            &garbage_bytes[..],
            &local_version_buffer[..],
        ]
        .concat()
    }

    #[test]
    fn test_handshake_session_reader() {
        let mut init_rng = StdRng::seed_from_u64(42);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let init_handshake = Handshake::<handshake::Initialized>::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            &mut init_rng,
            &secp,
        )
        .unwrap();

        // Generate responder messages with garbage and decoys.
        let resp_garbage = b"responder garbage";
        let resp_decoys: &[&[u8]] = &[b"decoy1", b"another decoy packet"];
        let mut messages = generate_handshake_messages(
            1042,
            42,
            Role::Responder,
            Some(resp_garbage),
            Some(resp_decoys),
        );

        // Add one extra byte that should be left for the session reader.
        let session_byte = 0x42u8;
        messages.push(session_byte);

        let reader = Cursor::new(messages);
        let mut writer = Vec::new();

        let result = handshake_with_initialized(init_handshake, None, None, reader, &mut writer);

        // Verify the session reader contains exactly the extra byte we added.
        let (_, _, mut session_reader) = result.unwrap();
        let mut buffer = [0u8; 1];
        match session_reader.read(&mut buffer) {
            Ok(1) => {
                assert_eq!(
                    buffer[0], session_byte,
                    "Session reader should contain the extra byte"
                );
            }
            Ok(n) => panic!("Expected to read 1 byte but read {}", n),
            Err(e) => panic!("Unexpected error reading from SessionReader: {}", e),
        }
    }
}
