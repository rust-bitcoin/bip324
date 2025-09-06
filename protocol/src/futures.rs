// SPDX-License-Identifier: CC0-1.0

//! Future-based asynchronous interfaces for establishing and using BIP-324
//! encrypted connections over AsyncRead/AsyncWrite transports.
//! It is only available when the `tokio` feature is enabled.
//!
//! # Performance Note
//!
//! The BIP-324 protocol performs many small reads (3-byte length prefixes,
//! 16-byte terminators, etc.). For optimal performance, wrap your reader
//! in a [`tokio::io::BufReader`].
//!
//! # Example
//!
//! ```no_run
//! use bip324::futures::Protocol;
//! use bip324::io::Payload;
//! use bip324::Role;
//! use tokio::net::TcpStream;
//! use tokio::io::BufReader;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to a Bitcoin node
//! let stream = TcpStream::connect("127.0.0.1:8333").await?;
//!
//! // Split the stream for reading and writing
//! let (reader, writer) = stream.into_split();
//! let reader = BufReader::new(reader);
//!
//! // Bitcoin mainnet magic bytes
//! let magic = [0xF9, 0xBE, 0xB4, 0xD9];
//!
//! // Establish BIP-324 encrypted connection
//! let mut protocol = Protocol::new(
//!     magic,
//!     Role::Initiator,
//!     None,  // no garbage bytes
//!     None,  // no decoy packets
//!     reader,
//!     writer,
//! ).await?;
//!
//! // Send and receive encrypted messages
//! protocol.write(&Payload::genuine(b"Hello, world!".to_vec())).await?;
//! let response = protocol.read().await?;
//! println!("Received {} bytes", response.contents().len());
//! # Ok(())
//! # }
//! ```

use core::borrow::Borrow;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::vec;
use std::vec::Vec;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    handshake::{self, GarbageResult, VersionResult},
    io::{Payload, ProtocolError},
    Error, Handshake, InboundCipher, OutboundCipher, Role, MAX_PACKET_SIZE_FOR_ALLOCATION,
    NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINTOR_BYTES, NUM_LENGTH_BYTES,
};

/// An async reader that chains unconsumed handshake data with the underlying stream.
///
/// This type is returned from the async handshake process and ensures that any
/// unread bytes from the handshake (such as partial packets in the garbage buffer)
/// are read before data from the underlying stream.
///
/// # Implementation Note
///
/// Once Type Alias Impl Trait (TAIT) stabilizes, this should be simplified to a type alias.
pub struct ProtocolSessionReader<R> {
    /// Leftover bytes from the handshake that need to be read first.
    leftover: Vec<u8>,
    /// Current position in the leftover buffer.
    leftover_pos: usize,
    /// The underlying async reader.
    reader: R,
}

impl<R> ProtocolSessionReader<R> {
    /// Create a new async session reader from leftover handshake bytes and the underlying reader.
    fn new(leftover: Vec<u8>, reader: R) -> Self {
        Self {
            leftover,
            leftover_pos: 0,
            reader,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProtocolSessionReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Manually implement AsyncRead chaining instead of using
        // tokio's chain() because chain() returns an unnameable `impl AsyncRead` type.

        // Get a normal mutable reference from the Pin.
        // This is safe because R: Unpin.
        let this = self.get_mut();

        // First, drain any leftover bytes from the handshake
        if this.leftover_pos < this.leftover.len() {
            let remaining = &this.leftover[this.leftover_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.leftover_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Once leftover is drained, delegate to the underlying reader.
        // We need to re-pin the reader for the async read call.
        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}

/// Perform an async BIP-324 handshake and return ready-to-use session components.
///
/// This function is *not* cancellation safe.
///
/// # Arguments
///
/// * `network` - Network which both parties are operating on.
/// * `role` - Role in handshake, initiator or responder.
/// * `garbage` - Optional garbage bytes to send in handshake.
/// * `decoys` - Optional decoy packet contents bytes to send in handshake.
/// * `reader` - Async buffer to read packets sent by peer (takes ownership).
/// * `writer` - Async buffer to write packets to peer (takes mutable reference).
///
/// # Reader Transformation
///
/// The I/O reader is transformed in order to handle possible over-read
/// scenarios while attempting to detect the remote's garbage terminator.
///
/// # Returns
///
/// A `Result` containing:
///   * `Ok((InboundCipher, OutboundCipher, ProtocolSessionReader<R>))`: Ready-to-use session components.
///   * `Err(ProtocolError)`: An error that occurred during the handshake.
///
/// # Errors
///
/// * `Io` - Includes a flag for if the remote probably only understands the V1 protocol.
pub async fn handshake<R, W>(
    magic: impl Borrow<[u8; 4]>,
    role: Role,
    garbage: Option<Vec<u8>>,
    decoys: Option<Vec<Vec<u8>>>,
    mut reader: R,
    writer: &mut W,
) -> Result<(InboundCipher, OutboundCipher, ProtocolSessionReader<R>), ProtocolError>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Unpin,
{
    // Convert to references for the lower-level handshake methods.
    let garbage_ref = garbage.as_deref();
    // Convert Vec<Vec<u8>> to &[&[u8]] if present. Need the intermediate Vec<&[u8]> value
    // to ensure the vector of references lives through the function.
    let decoy_refs: Option<Vec<&[u8]>> = decoys
        .as_ref()
        .map(|vecs| vecs.iter().map(Vec::as_slice).collect());
    let decoys_ref = decoy_refs.as_deref();

    let handshake = Handshake::<handshake::Initialized>::new(magic, role)?;

    // Send local public key and optional garbage.
    let key_buffer_len = Handshake::<handshake::Initialized>::send_key_len(garbage_ref);
    let mut key_buffer = vec![0u8; key_buffer_len];
    let handshake = handshake.send_key(garbage_ref, &mut key_buffer)?;
    writer.write_all(&key_buffer).await?;
    writer.flush().await?;

    // Read remote's public key.
    let mut remote_ellswift_buffer = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
    reader.read_exact(&mut remote_ellswift_buffer).await?;
    let handshake = handshake.receive_key(remote_ellswift_buffer)?;

    // Send garbage terminator, decoys, and version.
    let version_buffer_len = Handshake::<handshake::ReceivedKey>::send_version_len(decoys_ref);
    let mut version_buffer = vec![0u8; version_buffer_len];
    let handshake = handshake.send_version(&mut version_buffer, decoys_ref)?;
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
                // The 256 bytes is a bit arbitrary. There is a max of 4095, but not sure
                // all of that should be allocated right away.
                let mut temp = vec![0u8; 256];
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

    // Process remaining bytes for decoy packets and version.
    let leftover_bytes = garbage_buffer[garbage_bytes..].to_vec();
    let mut session_reader = ProtocolSessionReader::new(leftover_bytes, reader);
    let mut length_bytes = [0u8; NUM_LENGTH_BYTES];
    loop {
        // Decrypt packet length.
        session_reader.read_exact(&mut length_bytes).await?;
        let packet_len = handshake.decrypt_packet_len(length_bytes)?;
        if packet_len > MAX_PACKET_SIZE_FOR_ALLOCATION {
            return Err(ProtocolError::Internal(Error::PacketTooBig));
        }

        // Process packet.
        let mut packet_bytes = vec![0u8; packet_len];
        session_reader.read_exact(&mut packet_bytes).await?;
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

/// A protocol session with handshake and send/receive packet management.
pub struct Protocol<R, W> {
    reader: ProtocolReader<R>,
    writer: ProtocolWriter<W>,
}

impl<R, W> Protocol<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// New protocol session which completes the initial handshake and returns a handler.
    ///
    /// This function is *not* cancellation safe.
    ///
    /// # Performance Note
    ///
    /// For optimal performance, wrap your `reader` in a [`tokio::io::BufReader`].
    /// The protocol makes many small reads during handshake and operation.
    ///
    /// # Arguments
    ///
    /// * `network` - Network which both parties are operating on.
    /// * `role` - Role in handshake, initiator or responder.
    /// * `garbage` - Optional garbage bytes to send in handshake.
    /// * `decoys` - Optional decoy packet contents bytes to send in handshake.
    /// * `reader` - Asynchronous buffer to read packets sent by peer (takes ownership).
    /// * `writer` - Asynchronous buffer to write packets to peer (takes ownership).
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
    pub async fn new(
        magic: impl Borrow<[u8; 4]>,
        role: Role,
        garbage: Option<Vec<u8>>,
        decoys: Option<Vec<Vec<u8>>>,
        reader: R,
        mut writer: W,
    ) -> Result<Protocol<R, W>, ProtocolError> {
        let (inbound_cipher, outbound_cipher, session_reader) =
            handshake(magic, role, garbage, decoys, reader, &mut writer).await?;

        Ok(Protocol {
            reader: ProtocolReader {
                inbound_cipher,
                reader: session_reader,
                state: DecryptState::init_reading_length(),
            },
            writer: ProtocolWriter {
                outbound_cipher,
                writer,
            },
        })
    }

    /// Split the protocol into a separate reader and writer.
    pub fn into_split(self) -> (ProtocolReader<R>, ProtocolWriter<W>) {
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
    pub async fn read(&mut self) -> Result<Payload, ProtocolError> {
        self.reader.read().await
    }

    /// Encrypt and write a packet to the underlying writer.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload to encrypt and send.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok()`: On successful payload encryption and packet send.
    ///   * `Err(ProtocolError)`: An error that occurred during the encryption or write.
    pub async fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        self.writer.write(payload).await
    }
}

/// State machine of an asynchronous packet read.
///
/// This maintains state between await points to ensure cancellation safety.
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
pub struct ProtocolReader<R> {
    inbound_cipher: InboundCipher,
    reader: ProtocolSessionReader<R>,
    state: DecryptState,
}

impl<R> ProtocolReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    /// Decrypt contents of received packet from buffer.
    ///
    /// This function is cancellation safe.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Payload)`: A decrypted payload with packet type.
    ///   * `Err(ProtocolError)`: An error that occurred during the read or decryption.
    pub async fn read(&mut self) -> Result<Payload, ProtocolError> {
        // Storing state between async reads to make function cancellation safe.
        loop {
            match &mut self.state {
                DecryptState::ReadingLength {
                    length_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < NUM_LENGTH_BYTES {
                        *bytes_read += self.reader.read(&mut length_bytes[*bytes_read..]).await?;
                    }

                    let packet_bytes_len = self.inbound_cipher.decrypt_packet_len(*length_bytes);
                    self.state = DecryptState::init_reading_payload(packet_bytes_len);
                }
                DecryptState::ReadingPayload {
                    packet_bytes,
                    bytes_read,
                } => {
                    while *bytes_read < packet_bytes.len() {
                        *bytes_read += self.reader.read(&mut packet_bytes[*bytes_read..]).await?;
                    }

                    let plaintext_len = InboundCipher::decryption_buffer_len(packet_bytes.len());
                    let mut plaintext_buffer = vec![0u8; plaintext_len];
                    self.inbound_cipher
                        .decrypt(packet_bytes, &mut plaintext_buffer, None)?;
                    self.state = DecryptState::init_reading_length();
                    return Ok(Payload::decrypted(plaintext_buffer));
                }
            }
        }
    }

    /// Consume the protocol reader in exchange for the underlying inbound cipher and reader.
    pub fn into_inner(self) -> (InboundCipher, ProtocolSessionReader<R>) {
        (self.inbound_cipher, self.reader)
    }
}

/// Manages an async buffer to automatically encrypt and send contents in packets.
pub struct ProtocolWriter<W> {
    outbound_cipher: OutboundCipher,
    writer: W,
}

impl<W> ProtocolWriter<W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Encrypt payload and write packet buffer.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload to encrypt and send.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok()`: On successful payload encryption and packet send.
    ///   * `Err(ProtocolError)`: An error that occurred during the encryption or write.
    pub async fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        let packet_len = OutboundCipher::encryption_buffer_len(payload.contents().len());
        let mut packet_buffer = vec![0u8; packet_len];

        self.outbound_cipher.encrypt(
            payload.contents(),
            &mut packet_buffer,
            payload.packet_type(),
            None,
        )?;

        self.writer.write_all(&packet_buffer).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Consume the protocol writer in exchange for the underlying outbound cipher and writer.
    pub fn into_inner(self) -> (OutboundCipher, W) {
        (self.outbound_cipher, self.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

    #[tokio::test]
    async fn test_async_handshake_functions() {
        use tokio::io::duplex;

        // Create two duplex channels to simulate network connection.
        let (local_stream, remote_stream) = duplex(1024);
        let (local_read, mut local_write) = tokio::io::split(local_stream);
        let (remote_read, mut remote_write) = tokio::io::split(remote_stream);

        let local_handshake = tokio::spawn(async move {
            handshake(
                MAGIC,
                Role::Initiator,
                Some(b"local garbage".to_vec()),
                Some(vec![b"local decoy".to_vec()]),
                local_read,
                &mut local_write,
            )
            .await
        });

        let remote_handshake = tokio::spawn(async move {
            handshake(
                MAGIC,
                Role::Responder,
                Some(b"remote garbage".to_vec()),
                Some(vec![b"remote decoy 1".to_vec(), b"remote decoy 2".to_vec()]),
                remote_read,
                &mut remote_write,
            )
            .await
        });

        let (local_result, remote_result) = tokio::join!(local_handshake, remote_handshake);
        local_result.unwrap().unwrap();
        remote_result.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_async_handshake_packet_too_big_protection() {
        // Verifies that the async handshake properly rejects packets
        // that would require excessive memory allocation.
        use tokio::io::duplex;

        let (local_stream, remote_stream) = duplex(MAX_PACKET_SIZE_FOR_ALLOCATION * 2);
        let (local_read, mut local_write) = tokio::io::split(local_stream);
        let (remote_read, mut remote_write) = tokio::io::split(remote_stream);

        let local_handshake = tokio::spawn(async move {
            handshake(
                MAGIC,
                Role::Initiator,
                None,
                None,
                local_read,
                &mut local_write,
            )
            .await
        });

        let remote_handshake = tokio::spawn(async move {
            let large_decoy = vec![0u8; MAX_PACKET_SIZE_FOR_ALLOCATION + 1];
            handshake(
                MAGIC,
                Role::Responder,
                None,
                Some(vec![large_decoy]),
                remote_read,
                &mut remote_write,
            )
            .await
        });

        let (local_result, _remote_result) = tokio::join!(local_handshake, remote_handshake);
        assert!(matches!(
            local_result.unwrap(),
            Err(ProtocolError::Internal(Error::PacketTooBig))
        ));
    }
}
