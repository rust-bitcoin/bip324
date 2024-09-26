// SPDX-License-Identifier: MIT OR Apache-2.0

//! BIP324 encrypted transport for exchanging bitcoin P2P *messages*. Much like TLS, a connection begins by exchanging ephemeral
//! elliptic curve public keys and performing a Diffie-Hellman handshake. Thereafter, each participant derives shared session secrets, and may
//! freely exchange encrypted packets.
//!
//! ## Packets
//!
//! A *packet* has the following layout:
//!   * *Length*   - 3-byte encoding of the length of the *contents* (note this does not include the header byte).
//!   * *Header*   - 1-byte for transport layer protocol flags, currently only used to flag decoy packets.
//!   * *Contents* - Variable length payload.
//!   * *Tag*      - 16-byte authentication tag.
//!
//! ## Application Messages
//!
//! Under the new V2 specification, P2P messages are encoded differently than V1.
//! Read more about the [specification](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki).
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod chacha20poly1305;
mod fschacha20poly1305;
mod hkdf;
#[cfg(feature = "std")]
pub mod serde;

use core::fmt;

pub use bitcoin::Network;

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use bitcoin::{
    hashes::sha256,
    secp256k1::{
        self,
        ellswift::{ElligatorSwift, ElligatorSwiftParty},
        PublicKey, Secp256k1, SecretKey, Signing,
    },
};
use fschacha20poly1305::{FSChaCha20, FSChaCha20Poly1305};
use hkdf::Hkdf;
use rand::Rng;

/// Number of bytes for the header holding protocol flags.
pub const NUM_HEADER_BYTES: usize = 1;
/// Number of bytes for the length encoding prefix of a packet.
pub const NUM_LENGTH_BYTES: usize = 3;
/// Value for header byte with the decoy flag flipped to true.
pub const DECOY_BYTE: u8 = 128;
/// Initial buffer for decoy and version packets in the handshake.
/// The buffer may have to be expanded if a party is sending large
/// decoy packets.
pub const NUM_INITIAL_HANDSHAKE_BUFFER_BYTES: usize = 4096;

// Version content is always empty for the current version of the protocol.
const VERSION_CONTENT: [u8; 0] = [];
// Number of bytes for the authentication tag of a packet.
const NUM_TAG_BYTES: usize = 16;
// Maximum number of garbage bytes to read before the terminator.
const MAX_NUM_GARBAGE_BYTES: usize = 4095;
// Number of bytes for the garbage terminator.
const NUM_GARBAGE_TERMINTOR_BYTES: usize = 16;
// Number of bytes per packet for static layout, everything not including contents.
const NUM_PACKET_OVERHEAD_BYTES: usize = NUM_LENGTH_BYTES + NUM_HEADER_BYTES + NUM_TAG_BYTES;
// Number of bytes in elligator swift key.
const NUM_ELLIGATOR_SWIFT_BYTES: usize = 64;

/// Errors encountered throughout the lifetime of a V2 connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encrypted text does not contain enough information to decrypt.
    CiphertextTooSmall,
    /// Allocated memory is too small for packet, returns
    /// total required bytes for the failed packet so the
    /// caller can re-allocate and re-attempt.
    BufferTooSmall { required_bytes: usize },
    /// The maximum amount of garbage bytes was exceeded in the handshake.
    MaxGarbageLength,
    /// A handshake step was not completed in the proper order.
    HandshakeOutOfOrder,
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
                "Buffer memory allocation too small, need at least {} bytes.",
                required_bytes
            ),
            Error::MaxGarbageLength => {
                write!(f, "More than 4095 bytes of garbage in the handshake.")
            }
            Error::HandshakeOutOfOrder => write!(f, "Handshake flow out of sequence."),
            Error::SecretGeneration(e) => write!(f, "Cannot generate secrets: {}.", e),
            Error::Decryption(e) => write!(f, "Decrytion error: {}.", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::CiphertextTooSmall => None,
            Error::MaxGarbageLength => None,
            Error::HandshakeOutOfOrder => None,
            Error::SecretGeneration(e) => Some(e),
            Error::Decryption(e) => Some(e),
            Error::BufferTooSmall { required_bytes: _ } => None,
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
                write!(f, "Cannot generate materials: {}.", e)
            }
            SecretGenerationError::Expansion(e) => write!(f, "Cannot expand key: {}.", e),
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

/// A point on the curve used to complete the handshake.
#[derive(Clone)]
pub struct EcdhPoint {
    secret_key: SecretKey,
    elligator_swift: ElligatorSwift,
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
    initiator_garbage_terminator: [u8; 16],
    responder_garbage_terminator: [u8; 16],
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
    /// Check if plaintext packet is a decoy.
    pub fn from_bytes(plaintext: &[u8]) -> Self {
        // Check if header byte has the decoy flag flipped.
        if plaintext.first() == Some(&DECOY_BYTE) {
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

/// Read packets over established encrypted channel from a peer.
#[derive(Clone)]
pub struct PacketReader {
    length_decoding_cipher: FSChaCha20,
    packet_decoding_aead: FSChaCha20Poly1305,
}

impl PacketReader {
    /// Decode the length, in bytes, of the rest of the inbound packet.
    ///
    /// Note that this does not decode to the length of contents described
    /// in BIP324, and is meant to represent the rest of the inbound packet
    /// which includes the header byte and the 16-byte authentication tag.
    ///
    /// # Arguments
    ///
    /// * `len_bytes` - The first three bytes of the ciphertext.
    ///
    /// # Returns
    ///
    /// The length of the rest of the packet.
    pub fn decypt_len(&mut self, len_bytes: [u8; 3]) -> usize {
        let mut enc_content_len = [0u8; 3];
        enc_content_len.copy_from_slice(&len_bytes);
        self.length_decoding_cipher.crypt(&mut enc_content_len);
        let mut content_slice = [0u8; 4];
        content_slice[0..3].copy_from_slice(&enc_content_len);
        let content_len = u32::from_le_bytes(content_slice);

        content_len as usize + NUM_HEADER_BYTES + NUM_TAG_BYTES
    }

    /// Decrypt the packet contents.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///                  the header, contents, and authentication tag.
    /// * `contents`   - Mutable buffer to write plaintext. Note that the first byte is the header byte
    ///                  containing protocol flags.
    /// * `aad`        - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(PacketType)`: A flag indicating if the decoded packet is a decoy or not.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    /// * `BufferTooSmall `    - Contents buffer argument is not large enough for plaintext.
    /// * Decryption errors for any failures such as a tag mismatch.
    pub fn decrypt_contents(
        &mut self,
        ciphertext: &[u8],
        contents: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<PacketType, Error> {
        let auth = aad.unwrap_or_default();
        // Check minimum size of ciphertext.
        if ciphertext.len() < NUM_TAG_BYTES {
            return Err(Error::CiphertextTooSmall);
        }
        let (msg, tag) = ciphertext.split_at(ciphertext.len() - NUM_TAG_BYTES);
        // Check that the contents buffer is large enough.
        if contents.len() < msg.len() {
            return Err(Error::BufferTooSmall {
                required_bytes: msg.len(),
            });
        }
        contents[0..msg.len()].copy_from_slice(msg);
        self.packet_decoding_aead.decrypt(
            auth,
            &mut contents[0..msg.len()],
            tag.try_into().expect("16 byte tag"),
        )?;

        Ok(PacketType::from_bytes(contents))
    }

    /// Decrypt the packet contents.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The packet from the peer excluding the first 3 length bytes. It should contain
    ///                  the header, contents, and authentication tag.
    /// * `aad`        - Optional associated authenticated data.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    ///   * `Ok(Some(Vec<u8>))`: The plaintext contents in a byte vector if it is not a decoy packet.
    ///   * `Err(Error)`: An error that occurred during decryption.
    ///
    /// # Errors
    ///
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet.
    #[cfg(feature = "alloc")]
    pub fn decrypt_contents_with_alloc(
        &mut self,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut contents = vec![0u8; ciphertext.len() - NUM_TAG_BYTES];
        match self.decrypt_contents(ciphertext, &mut contents, aad)? {
            PacketType::Decoy => Ok(None),
            PacketType::Genuine => {
                // Drop the header byte.
                contents.remove(0);
                Ok(Some(contents))
            }
        }
    }
}

/// Prepare packets to be sent over encrypted channel to a peer.
#[derive(Clone)]
pub struct PacketWriter {
    length_encoding_cipher: FSChaCha20,
    packet_encoding_aead: FSChaCha20Poly1305,
}

impl PacketWriter {
    /// Encrypt plaintext bytes and serialize into a packet to be sent over the wire.
    ///
    /// # Arguments
    ///
    /// * `plaintext`   - Plaintext contents to be encrypted.
    /// * `aad`         - Optional associated authenticated data.
    /// * `packet`      - Buffer to write backet bytes too which must have enough capacity
    ///                   for the plaintext length in bytes + 20 (length, header, and tag bytes).
    /// * `packet_type` - Is this a genuine packet or a decoy.
    ///
    /// # Errors
    ///
    /// * `Error::BufferTooSmall` - Buffer does not have enough allocated memory for the
    ///                             ciphertext plus the 20 bytes needed for the length, header, and tag bytes.
    pub fn encrypt_packet(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        packet: &mut [u8],
        packet_type: PacketType,
    ) -> Result<(), Error> {
        // Validate buffer capacity.
        if packet.len() < plaintext.len() + NUM_PACKET_OVERHEAD_BYTES {
            return Err(Error::BufferTooSmall {
                required_bytes: plaintext.len() + NUM_PACKET_OVERHEAD_BYTES,
            });
        }

        let plaintext_length = plaintext.len();
        let header_index = NUM_LENGTH_BYTES + NUM_HEADER_BYTES - 1;
        let plaintext_start_index = header_index + 1;
        let plaintext_end_index = plaintext_start_index + plaintext_length;

        // Set header byte.
        packet[header_index] = packet_type.to_byte();
        packet[plaintext_start_index..plaintext_end_index].copy_from_slice(plaintext);

        // Encrypt header byte and plaintext in place and produce authentication tag.
        let auth = aad.unwrap_or_default();
        let tag = self
            .packet_encoding_aead
            .encrypt(auth, &mut packet[header_index..plaintext_end_index]);

        // Encrypt plaintext length.
        let mut content_len = [0u8; 3];
        content_len.copy_from_slice(&(plaintext_length as u32).to_le_bytes()[0..NUM_LENGTH_BYTES]);
        self.length_encoding_cipher.crypt(&mut content_len);

        // Copy over encrypted length and the tag to the final packet (plaintext already encrypted).
        packet[0..NUM_LENGTH_BYTES].copy_from_slice(&content_len);
        packet[plaintext_end_index..(plaintext_end_index + NUM_TAG_BYTES)].copy_from_slice(&tag);

        Ok(())
    }

    /// Encrypt plaintext bytes and serialize into a packet to be sent over the wire
    /// and handle necessary memory allocation.
    ///
    /// * `plaintext`   - Plaintext content to be encrypted.
    /// * `aad`         - Optional associated authenticated data.
    /// * `packet_type` - Is this a genuine packet or a decoy.
    #[cfg(feature = "alloc")]
    pub fn encrypt_packet_with_alloc(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        packet_type: PacketType,
    ) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0u8; plaintext.len() + NUM_PACKET_OVERHEAD_BYTES];
        self.encrypt_packet(plaintext, aad, &mut packet, packet_type)?;
        Ok(packet)
    }
}

/// Encrypt and decrypt packets with a peer.
#[derive(Clone)]
pub struct PacketHandler {
    /// A unique identifier for the communication session.
    pub session_id: [u8; 32],
    /// Decrypt packets.
    pub packet_reader: PacketReader,
    /// Encrypt packets.
    pub packet_writer: PacketWriter,
}

impl PacketHandler {
    fn new(materials: SessionKeyMaterial, role: Role) -> Self {
        match role {
            Role::Initiator => {
                let length_encoding_cipher = FSChaCha20::new(materials.initiator_length_key);
                let length_decoding_cipher = FSChaCha20::new(materials.responder_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                PacketHandler {
                    session_id: materials.session_id,
                    packet_reader: PacketReader {
                        length_decoding_cipher,
                        packet_decoding_aead: packet_decoding_cipher,
                    },
                    packet_writer: PacketWriter {
                        length_encoding_cipher,
                        packet_encoding_aead: packet_encoding_cipher,
                    },
                }
            }
            Role::Responder => {
                let length_encoding_cipher = FSChaCha20::new(materials.responder_length_key);
                let length_decoding_cipher = FSChaCha20::new(materials.initiator_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                PacketHandler {
                    session_id: materials.session_id,
                    packet_reader: PacketReader {
                        length_decoding_cipher,
                        packet_decoding_aead: packet_decoding_cipher,
                    },
                    packet_writer: PacketWriter {
                        length_encoding_cipher,
                        packet_encoding_aead: packet_encoding_cipher,
                    },
                }
            }
        }
    }

    /// Split the handler into separate reader and a writer.
    pub fn into_split(self) -> (PacketReader, PacketWriter) {
        (self.packet_reader, self.packet_writer)
    }
}

fn gen_key(rng: &mut impl Rng) -> Result<SecretKey, Error> {
    let mut buffer = [0u8; 32];
    rng.fill(&mut buffer[..]);
    let sk = SecretKey::from_slice(&buffer)?;
    Ok(sk)
}

fn new_elligator_swift<C: Signing>(
    sk: SecretKey,
    curve: &Secp256k1<C>,
) -> Result<ElligatorSwift, Error> {
    let pk = PublicKey::from_secret_key(curve, &sk);
    Ok(ElligatorSwift::from_pubkey(pk))
}

fn get_shared_secrets(
    a: ElligatorSwift,
    b: ElligatorSwift,
    secret: SecretKey,
    party: ElligatorSwiftParty,
    network: Network,
) -> Result<SessionKeyMaterial, Error> {
    let data = "bip324_ellswift_xonly_ecdh".as_bytes();
    let ecdh_sk = ElligatorSwift::shared_secret(a, b, secret, party, Some(data));
    initialize_session_key_material(ecdh_sk.as_secret_bytes(), network)
}

fn initialize_session_key_material(
    ikm: &[u8],
    network: Network,
) -> Result<SessionKeyMaterial, Error> {
    let ikm_salt = "bitcoin_v2_shared_secret".as_bytes();
    let magic = network.magic().to_bytes();
    let salt = [ikm_salt, &magic].concat();
    let hk = Hkdf::<sha256::Hash>::new(salt.as_slice(), ikm);
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

/// Handshake state-machine to establish the secret material in the communication channel.
///
/// A handshake is first initialized to create local materials needed to setup communication
/// channel between an *initiator* and a *responder*. The next step is to call `complete_materials`
/// no matter if initiator or responder, however the responder should already have the
/// necessary materials from their peers request. `complete_materials` creates the response
/// packet to be sent from each peer and `authenticate_garbage_and_version` is then used
/// to verify the handshake. Finally, the `finalized` method is used to consumer the handshake
/// and return a packet handler for further communication on the channel.
pub struct Handshake<'a> {
    /// Bitcoin network both peers are operating on.
    network: Network,
    /// Local role in the handshake, initiator or responder.
    role: Role,
    /// Local point for key exchange.
    point: EcdhPoint,
    /// Optional garbage bytes to send along in handshake.
    garbage: Option<&'a [u8]>,
    /// Peers expected garbage terminator.
    remote_garbage_terminator: Option<[u8; NUM_GARBAGE_TERMINTOR_BYTES]>,
    /// Packet handler output.
    packet_handler: Option<PacketHandler>,
    /// Decrypted length for next packet. Store state between authentication attempts to avoid resetting ciphers.
    current_packet_length_bytes: Option<usize>,
    /// Processesed buffer index. Store state between authentication attempts to avoid resetting ciphers.
    current_buffer_index: usize,
}

impl<'a> Handshake<'a> {
    /// Initialize a V2 transport handshake with a peer.
    ///
    /// # Arguments
    ///
    /// * `network` - The bitcoin network which both peers operate on.
    /// * `garbage` - Optional garbage to send in handshake.
    /// * `buffer`  - Packet buffer to send to peer which will include initial materials for handshake + garbage.
    ///
    /// # Returns
    ///
    /// An initialized handshake which must be finalized.
    ///
    /// # Errors
    ///
    /// Fails if their was an error generating the keypair.
    #[cfg(feature = "std")]
    pub fn new(
        network: Network,
        role: Role,
        garbage: Option<&'a [u8]>,
        buffer: &mut [u8],
    ) -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let curve = Secp256k1::signing_only();
        Self::new_with_rng(network, role, garbage, buffer, &mut rng, &curve)
    }

    /// Initialize a V2 transport handshake with a peer.
    ///
    /// # Arguments
    ///
    /// * `network` - The bitcoin network which both peers operate on.
    /// * `garbage` - Optional garbage to send in handshake.    
    /// * `buffer`  - Packet buffer to send to peer which will include initial materials for handshake + garbage.
    /// * `rng`     - Supplied Random Number Generator.
    /// * `curve`   - Supplied secp256k1 context.
    ///
    /// # Returns
    ///
    /// An initialized handshake which must be finalized.
    ///
    /// # Errors
    ///
    /// Fails if their was an error generating the keypair.
    pub fn new_with_rng<C: Signing>(
        network: Network,
        role: Role,
        garbage: Option<&'a [u8]>,
        buffer: &mut [u8],
        rng: &mut impl Rng,
        curve: &Secp256k1<C>,
    ) -> Result<Self, Error> {
        let sk = gen_key(rng)?;
        let es = new_elligator_swift(sk, curve)?;
        let point = EcdhPoint {
            secret_key: sk,
            elligator_swift: es,
        };

        buffer[0..64].copy_from_slice(&point.elligator_swift.to_array());
        if let Some(garbage) = garbage {
            buffer[64..64 + garbage.len()].copy_from_slice(garbage);
        }

        Ok(Handshake {
            network,
            role,
            point,
            garbage,
            remote_garbage_terminator: None,
            packet_handler: None,
            current_packet_length_bytes: None,
            current_buffer_index: 0,
        })
    }

    /// Complete the secret material handshake and send the version packet to peer.
    ///
    /// # Arguments
    ///
    /// * `their_elliswift` - The key material of the remote peer.
    /// * `response_buffer` - Buffer to write response for remote peer which includes the garbage terminator and version packet.
    /// * `decoys`          - Contents for decoy packets sent before version packet.
    pub fn complete_materials(
        &mut self,
        their_elliswift: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
        response_buffer: &mut [u8],
        decoys: Option<&[&[u8]]>,
    ) -> Result<(), Error> {
        let theirs = ElligatorSwift::from_array(their_elliswift);

        // Line up appropriate materials based on role and some
        // garbage terminator haggling.
        let materials = match self.role {
            Role::Initiator => {
                let materials = get_shared_secrets(
                    self.point.elligator_swift,
                    theirs,
                    self.point.secret_key,
                    ElligatorSwiftParty::A,
                    self.network,
                )?;
                response_buffer[..NUM_GARBAGE_TERMINTOR_BYTES]
                    .copy_from_slice(&materials.initiator_garbage_terminator);
                self.remote_garbage_terminator = Some(materials.responder_garbage_terminator);

                materials
            }
            Role::Responder => {
                let materials = get_shared_secrets(
                    theirs,
                    self.point.elligator_swift,
                    self.point.secret_key,
                    ElligatorSwiftParty::B,
                    self.network,
                )?;
                response_buffer[..NUM_GARBAGE_TERMINTOR_BYTES]
                    .copy_from_slice(&materials.responder_garbage_terminator);
                self.remote_garbage_terminator = Some(materials.initiator_garbage_terminator);

                materials
            }
        };

        let mut packet_handler = PacketHandler::new(materials, self.role);
        let mut start_index = NUM_GARBAGE_TERMINTOR_BYTES;

        // Write any decoy packets and then the version packet.
        // The first packet, no matter if decoy or genuinie version packet, needs
        // to authenticate the garbage previously sent.
        if let Some(decoys) = decoys {
            for (i, decoy) in decoys.iter().enumerate() {
                let end_index = start_index + decoy.len() + NUM_PACKET_OVERHEAD_BYTES;
                packet_handler.packet_writer.encrypt_packet(
                    decoy,
                    if i == 0 { self.garbage } else { None },
                    &mut response_buffer[start_index..end_index],
                    PacketType::Decoy,
                )?;

                start_index = end_index;
            }
        }

        packet_handler.packet_writer.encrypt_packet(
            &VERSION_CONTENT,
            if decoys.is_none() { self.garbage } else { None },
            &mut response_buffer
                [start_index..start_index + VERSION_CONTENT.len() + NUM_PACKET_OVERHEAD_BYTES],
            PacketType::Genuine,
        )?;

        self.packet_handler = Some(packet_handler);

        Ok(())
    }

    /// Authenticate the channel and manage the memory allocation required.
    ///
    /// This function wraps [`authenticate_garbage_and_version`] and handles buffer allocation.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Should contain all garbage, the garbage terminator, any decoy packets, and finally the version packet received from peer.
    ///
    /// # Errors
    ///
    /// Returns the same errors of [`authenticate_garbage_and_version`], except `BufferTooSmall` is managed internally.
    #[cfg(feature = "alloc")]
    pub fn authenticate_garbage_and_version_with_alloc(
        &mut self,
        buffer: &[u8],
    ) -> Result<(), Error> {
        let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES];

        loop {
            match self.authenticate_garbage_and_version(buffer, &mut packet_buffer) {
                Ok(()) => return Ok(()),
                Err(Error::BufferTooSmall { required_bytes }) => {
                    packet_buffer.resize(required_bytes, 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Authenticate the channel.
    ///
    /// Designed to be called multiple times until succesful in order to flush
    /// garbage and decoy packets from channel. If a `BufferTooSmall ` is
    /// returned, the buffer should be extended until `BufferTooSmall ` is
    /// not returned. All other errors are fatal for the handshake and it should
    /// be completely restarted.
    ///
    /// # Arguments
    ///
    /// * `buffer`        - Should contain all garbage, the garbage terminator, any decoy packets, and finally the version packet received from peer.
    /// * `packet_buffer` - Required memory allocation for decrypting decoy and version packets.
    ///
    /// # Error    
    ///
    /// * `CiphertextTooSmall`    - The buffer did not contain all required information and should be extended (e.g. read more off a socket) and authentication re-tried.
    /// * `BufferTooSmall`        - The supplied packet_buffer is not large enough for decrypting the decoy and version packets.
    /// * `HandshakeOutOfOrder`   - The handshake sequence is in a bad state and should be restarted.
    /// * `MaxGarbageLength`      - Buffer did not contain the garbage terminator, should not be retried.
    pub fn authenticate_garbage_and_version(
        &mut self,
        buffer: &[u8],
        packet_buffer: &mut [u8],
    ) -> Result<(), Error> {
        // Find the end of the garbage.
        let (garbage, ciphertext) = split_garbage(
            buffer,
            self.remote_garbage_terminator
                .ok_or(Error::HandshakeOutOfOrder)?,
        )?;

        // Flag to track if the version packet has been received to signal the end of the handshake.
        let mut found_version_packet = false;

        // The first packet, even if it is a decoy packet,
        // is used to authenticate the received garbage through
        // the AAD.
        if self.current_buffer_index == 0 {
            found_version_packet = self.decrypt_packet(ciphertext, packet_buffer, Some(garbage))?;
        }

        // If the first packet is a decoy, or if this is a follow up
        // authentication attempt, the decoys need to be flushed and
        // the version packet found.
        //
        // The version packet is essentially ignored in the current
        // version of the protocol, but it does move the cipher
        // states forward. It could be extended in the future.
        while !found_version_packet {
            found_version_packet = self.decrypt_packet(ciphertext, packet_buffer, None)?;
        }

        Ok(())
    }

    /// Decrypt the next packet in the buffer while
    /// book keeping relevant lengths and indexes. This allows
    /// the buffer to be re-processed without throwing off
    /// the state of the ciphers.
    ///
    /// # Returns
    ///
    /// True if the decrypted packet is the version packet.
    fn decrypt_packet(
        &mut self,
        ciphertext: &[u8],
        packet_buffer: &mut [u8],
        garbage: Option<&[u8]>,
    ) -> Result<bool, Error> {
        let packet_handler = self
            .packet_handler
            .as_mut()
            .ok_or(Error::HandshakeOutOfOrder)?;

        if self.current_packet_length_bytes.is_none() {
            // Bounds check on the input buffer.
            if ciphertext.len() < self.current_buffer_index + NUM_LENGTH_BYTES {
                return Err(Error::CiphertextTooSmall);
            }
            let packet_length = packet_handler.packet_reader.decypt_len(
                ciphertext[self.current_buffer_index..self.current_buffer_index + NUM_LENGTH_BYTES]
                    .try_into()
                    .expect("Buffer slice must be exactly 3 bytes long"),
            );
            // Hang on to decrypted length incase follow up steps fail
            // and another authentication attempt is required. Avoids
            // throwing off the cipher state.
            self.current_packet_length_bytes = Some(packet_length);
        }

        let packet_length = self
            .current_packet_length_bytes
            .ok_or(Error::HandshakeOutOfOrder)?;

        // Bounds check on input buffer.
        if ciphertext.len() < self.current_buffer_index + NUM_LENGTH_BYTES + packet_length {
            return Err(Error::CiphertextTooSmall);
        }
        packet_handler.packet_reader.decrypt_contents(
            &ciphertext[self.current_buffer_index + NUM_LENGTH_BYTES
                ..self.current_buffer_index + NUM_LENGTH_BYTES + packet_length],
            packet_buffer,
            garbage,
        )?;

        // Mark current decryption point in the buffer.
        self.current_buffer_index = self.current_buffer_index + NUM_LENGTH_BYTES + packet_length;
        self.current_packet_length_bytes = None;

        // The version packet is currently just an empty packet.
        Ok(matches!(
            PacketType::from_bytes(packet_buffer),
            PacketType::Genuine
        ))
    }

    /// Complete the handshake and return the packet handler for further communication.
    ///
    /// # Error    
    ///
    /// * `HandshakeOutOfOrder` - The handshake sequence is in a bad state and should be restarted.
    pub fn finalize(self) -> Result<PacketHandler, Error> {
        let packet_handler = self.packet_handler.ok_or(Error::HandshakeOutOfOrder)?;
        Ok(packet_handler)
    }
}

/// Split off garbage in the buffer on the garbage terminator.
///
/// # Returns
///
/// A `Result` containing the garbage and the remaining ciphertext not including the terminator.
///
/// # Error
///
/// * `CiphertextTooSmall`    - Buffer did not contain a garbage terminator.
/// * `MaxGarbageLength`      - Buffer did not contain the garbage terminator and contains too much garbage, should not be retried.
fn split_garbage(
    buffer: &[u8],
    garbage_term: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
) -> Result<(&[u8], &[u8]), Error> {
    if let Some(index) = buffer
        .windows(garbage_term.len())
        .position(|window| window == garbage_term)
    {
        Ok((&buffer[..index], &buffer[(index + garbage_term.len())..]))
    } else if buffer.len() >= (MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES) {
        Err(Error::MaxGarbageLength)
    } else {
        // Terminator not found, the buffer needs more information.
        Err(Error::CiphertextTooSmall)
    }
}

#[cfg(test)]
mod tests {
    //! Any tests requiring a random number generator are currently
    //! gated with the std feature flag.

    use super::*;
    use core::str::FromStr;
    use hex::prelude::*;

    #[cfg(feature = "std")]
    fn gen_garbage(garbage_len: u32, rng: &mut impl Rng) -> Vec<u8> {
        let buffer: Vec<u8> = (0..garbage_len).map(|_| rng.gen()).collect();
        buffer
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_sec_keygen() {
        let mut rng = rand::thread_rng();
        gen_key(&mut rng).unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_initial_message() {
        use alloc::string::ToString;

        let mut message = [0u8; 64];
        let handshake =
            Handshake::new(Network::Bitcoin, Role::Initiator, None, &mut message).unwrap();
        let message = message.to_lower_hex_string();
        let es = handshake.point.elligator_swift.to_string();
        assert!(message.contains(&es))
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_message_response() {
        let mut message = [0u8; 64];
        Handshake::new(Network::Bitcoin, Role::Initiator, None, &mut message).unwrap();

        let mut response_message = [0u8; 100];
        let mut response = Handshake::new(
            Network::Bitcoin,
            Role::Responder,
            None,
            &mut response_message,
        )
        .unwrap();

        response
            .complete_materials(message, &mut response_message[64..], None)
            .unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_expand_extract() {
        let ikm = Vec::from_hex("c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592")
            .unwrap();
        let session_keys = initialize_session_key_material(&ikm, Network::Bitcoin).unwrap();
        assert_eq!(
            session_keys.session_id.to_lower_hex_string(),
            "ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5"
        );
    }

    #[test]
    fn test_shared_secret() {
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        assert_eq!(
            "9a6478b5fbab1f4dd2f78994b774c03211c78312786e602da75a0d1767fb55cf",
            session_keys.initiator_length_key.to_lower_hex_string()
        );
        assert_eq!(
            "7d0c7820ba6a4d29ce40baf2caa6035e04f1e1cefd59f3e7e59e9e5af84f1f51",
            session_keys.initiator_packet_key.to_lower_hex_string()
        );
        assert_eq!(
            "17bc726421e4054ac6a1d54915085aaa766f4d3cf67bbd168e6080eac289d15e",
            session_keys.responder_length_key.to_lower_hex_string()
        );
        assert_eq!(
            "9f0fc1c0e85fd9a8eee07e6fc41dba2ff54c7729068a239ac97c37c524cca1c0",
            session_keys.responder_packet_key.to_lower_hex_string()
        );
        assert_eq!(
            "faef555dfcdb936425d84aba524758f3",
            session_keys
                .initiator_garbage_terminator
                .to_lower_hex_string()
        );
        assert_eq!(
            "02cb8ff24307a6e27de3b4e7ea3fa65b",
            session_keys
                .responder_garbage_terminator
                .to_lower_hex_string()
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_max_garbage() {
        let too_much_garbage = vec![0; 4111];
        let garbage_terminator = [1; 16];
        let result = split_garbage(&too_much_garbage, garbage_terminator);
        assert!(matches!(result, Err(Error::MaxGarbageLength)));
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_packet_handler() {
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, Role::Responder);
        let message = b"Bitcoin rox!".to_vec();
        let enc_packet = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&message, None, PacketType::Decoy)
            .unwrap();
        let dec = bob_packet_handler
            .packet_reader
            .decrypt_contents_with_alloc(&enc_packet[NUM_LENGTH_BYTES..], None)
            .unwrap();
        assert_eq!(None, dec);
        let message = b"Windows sox!".to_vec();
        let enc_packet = bob_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
            .unwrap();
        let dec = alice_packet_handler
            .packet_reader
            .decrypt_contents_with_alloc(&enc_packet[NUM_LENGTH_BYTES..], None)
            .unwrap();
        assert_eq!(message, dec.unwrap());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_fuzz_packets() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, Role::Responder);
        // Force a rekey under the hood.
        for _ in 0..(224 + 100) {
            let message = gen_garbage(4095, &mut rng);
            let enc_packet = alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
                .unwrap();
            let dec_packet = bob_packet_handler
                .packet_reader
                .decrypt_contents_with_alloc(&enc_packet[NUM_LENGTH_BYTES..], None)
                .unwrap();
            assert_eq!(message, dec_packet.unwrap());
            let message = gen_garbage(420, &mut rng);
            let enc_packet = bob_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
                .unwrap();
            let dec_packet = alice_packet_handler
                .packet_reader
                .decrypt_contents_with_alloc(&enc_packet[NUM_LENGTH_BYTES..], None)
                .unwrap();
            assert_eq!(message, dec_packet.unwrap());
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_authenticated_garbage() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, Role::Responder);
        let auth_garbage = gen_garbage(200, &mut rng);
        let enc_packet = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&VERSION_CONTENT, Some(&auth_garbage), PacketType::Genuine)
            .unwrap();
        let _ = bob_packet_handler
            .packet_reader
            .decrypt_contents_with_alloc(&enc_packet[NUM_LENGTH_BYTES..], Some(&auth_garbage))
            .unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_full_handshake_with_garbage_and_decoys() {
        // Define the garbage and decoys that the initiator is sending to the responder.
        let initiator_garbage = vec![1u8, 2u8, 3u8];
        let initiator_decoys: Vec<&[u8]> = vec![&[6u8, 7u8], &[8u8, 0u8]];
        let num_initiator_decoys_bytes = initiator_decoys
            .iter()
            .map(|slice| slice.len())
            .sum::<usize>()
            + NUM_PACKET_OVERHEAD_BYTES * initiator_decoys.len();
        let num_initiator_version_bytes = VERSION_CONTENT.len() + NUM_PACKET_OVERHEAD_BYTES;
        // Buffer for initiator to write to and responder to read from.
        let mut initiator_buffer = vec![
            0u8;
            NUM_ELLIGATOR_SWIFT_BYTES
                + initiator_garbage.len()
                + NUM_GARBAGE_TERMINTOR_BYTES
                + num_initiator_decoys_bytes
                + num_initiator_version_bytes
        ];

        // Define the garbage and decoys that the responder is sending to the initiator.
        let responder_garbage = vec![4u8, 5u8];
        let responder_decoys: Vec<&[u8]> = vec![&[10u8, 11u8], &[12u8], &[13u8, 14u8, 15u8]];
        let num_responder_decoys_bytes = responder_decoys
            .iter()
            .map(|slice| slice.len())
            .sum::<usize>()
            + NUM_PACKET_OVERHEAD_BYTES * responder_decoys.len();
        let num_responder_version_bytes = VERSION_CONTENT.len() + NUM_PACKET_OVERHEAD_BYTES;
        // Buffer for responder to write to and initiator to read from.
        let mut responder_buffer = vec![
            0u8;
            NUM_ELLIGATOR_SWIFT_BYTES
                + responder_garbage.len()
                + NUM_GARBAGE_TERMINTOR_BYTES
                + num_responder_decoys_bytes
                + num_responder_version_bytes
        ];

        // The initiator's handshake writes its 64 byte elligator swift key and garbage to their buffer to send to the responder.
        let mut initiator_handshake = Handshake::new(
            Network::Bitcoin,
            Role::Initiator,
            Some(&initiator_garbage),
            &mut initiator_buffer[..NUM_ELLIGATOR_SWIFT_BYTES + initiator_garbage.len()],
        )
        .unwrap();

        // The responder also writes its 64 byte elligator swift key and garbage to their buffer to send to the initiator.
        let mut responder_handshake = Handshake::new(
            Network::Bitcoin,
            Role::Responder,
            Some(&responder_garbage),
            &mut responder_buffer[..NUM_ELLIGATOR_SWIFT_BYTES + responder_garbage.len()],
        )
        .unwrap();

        // The responder has received the initiator's initial material so can complete the secrets.
        // With the secrets calculated, the responder can send along the garbage terminator, decoys, and version packet.
        responder_handshake
            .complete_materials(
                initiator_buffer[..NUM_ELLIGATOR_SWIFT_BYTES]
                    .try_into()
                    .unwrap(),
                &mut responder_buffer[NUM_ELLIGATOR_SWIFT_BYTES + responder_garbage.len()..],
                Some(&responder_decoys),
            )
            .unwrap();

        // Once the initiator receives the responder's response it can also complete the secrets.
        // The initiator then needs to send along their recently calculated garbage terminator, decoys, and the version packet.
        initiator_handshake
            .complete_materials(
                responder_buffer[..NUM_ELLIGATOR_SWIFT_BYTES]
                    .try_into()
                    .unwrap(),
                &mut initiator_buffer[NUM_ELLIGATOR_SWIFT_BYTES + initiator_garbage.len()..],
                Some(&initiator_decoys),
            )
            .unwrap();

        // The initiator verifies the second half of the responders message which
        // includes the garbage, garbage terminator, decoys, and version packet.
        initiator_handshake
            .authenticate_garbage_and_version_with_alloc(
                &responder_buffer[NUM_ELLIGATOR_SWIFT_BYTES..],
            )
            .unwrap();

        // The responder verifies the second message from the initiator which
        // includes the garbage, garbage terminator, decoys, and version packet.
        responder_handshake
            .authenticate_garbage_and_version_with_alloc(
                &initiator_buffer[NUM_ELLIGATOR_SWIFT_BYTES..],
            )
            .unwrap();

        let mut alice = initiator_handshake.finalize().unwrap();
        let mut bob = responder_handshake.finalize().unwrap();

        let message = b"Hello world".to_vec();
        let encrypted_message_to_alice = bob
            .packet_writer
            .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
            .unwrap();
        let dec = alice
            .packet_reader
            .decrypt_contents_with_alloc(&encrypted_message_to_alice[NUM_LENGTH_BYTES..], None)
            .unwrap();
        assert_eq!(message, dec.unwrap());
        let message = b"g!".to_vec();
        let encrypted_message_to_bob = alice
            .packet_writer
            .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
            .unwrap();
        let dec = bob
            .packet_reader
            .decrypt_contents_with_alloc(&encrypted_message_to_bob[NUM_LENGTH_BYTES..], None)
            .unwrap();
        assert_eq!(message, dec.unwrap());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_partial_decodings() {
        let mut rng = rand::thread_rng();

        let mut init_message = vec![0u8; 64];
        let mut init_handshake =
            Handshake::new(Network::Bitcoin, Role::Initiator, None, &mut init_message).unwrap();

        let mut resp_message = vec![0u8; 100];
        let mut resp_handshake =
            Handshake::new(Network::Bitcoin, Role::Responder, None, &mut resp_message).unwrap();

        resp_handshake
            .complete_materials(
                init_message.try_into().unwrap(),
                &mut resp_message[64..],
                None,
            )
            .unwrap();
        let mut init_finalize_message = vec![0u8; 36];
        init_handshake
            .complete_materials(
                resp_message[0..64].try_into().unwrap(),
                &mut init_finalize_message,
                None,
            )
            .unwrap();

        init_handshake
            .authenticate_garbage_and_version_with_alloc(&resp_message[64..])
            .unwrap();
        resp_handshake
            .authenticate_garbage_and_version_with_alloc(&init_finalize_message)
            .unwrap();

        let mut alice = init_handshake.finalize().unwrap();
        let mut bob = resp_handshake.finalize().unwrap();

        let mut message_to_bob = Vec::new();
        let message = gen_garbage(420, &mut rng);
        let enc_packet = alice
            .packet_writer
            .encrypt_packet_with_alloc(&message, None, PacketType::Genuine)
            .unwrap();
        message_to_bob.extend(enc_packet);
        let alice_message_len = bob
            .packet_reader
            .decypt_len(message_to_bob[..3].try_into().unwrap());
        let contents = bob
            .packet_reader
            .decrypt_contents_with_alloc(&message_to_bob[3..3 + alice_message_len], None)
            .unwrap();
        assert_eq!(contents.unwrap(), message);
    }

    // The rest are sourced from [the BIP324 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv).

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_1() {
        let mut rng = rand::thread_rng();
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, Role::Responder);
        let first = gen_garbage(100, &mut rng);
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&first, None, PacketType::Genuine)
            .unwrap();
        let dec_packet = bob_packet_handler
            .packet_reader
            .decrypt_contents_with_alloc(&enc[NUM_LENGTH_BYTES..], None)
            .unwrap();
        assert_eq!(first, dec_packet.unwrap());
        let contents: Vec<u8> = vec![0x8e];
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Genuine)
            .unwrap();
        assert_eq!(
            enc,
            Vec::from_hex("7530d2a18720162ac09c25329a60d75adf36eda3c3").unwrap()
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_2() {
        let alice =
            SecretKey::from_str("1f9c581b35231838f0f17cf0c979835baccb7f3abbbb96ffcc318ab71e6e126f")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("a1855e10e94e00baa23041d916e259f7044e491da6171269694763f018c7e63693d29575dcb464ac816baa1be353ba12e3876cba7628bd0bd8e755e721eb0140").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let session_keys = get_shared_secrets(
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
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Responder);
        let contents: Vec<u8> = Vec::from_hex("3eb1d4e98035cfd8eeb29bac969ed3824a").unwrap();
        for _ in 0..999 {
            alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&Vec::new(), None, PacketType::Genuine)
                .unwrap();
        }
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Genuine)
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
    #[cfg(feature = "std")]
    fn test_vector_3() {
        let alice =
            SecretKey::from_str("0286c41cd30913db0fdff7a64ebda5c8e3e7cef10f2aebc00a7650443cf4c60d")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("d1ee8a93a01130cbf299249a258f94feb5f469e7d0f2f28f69ee5e9aa8f9b54a60f2c3ff2d023634ec7f4127a96cc11662e402894cf1f694fb9a7eaa5f1d9244").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff22d5e441524d571a52b3def126189d3f416890a99d4da6ede2b0cde1760ce2c3f98457ae").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex("054290a6c6ba8d80478172e89d32bf690913ae9835de6dcf206ff1f4d652286fe0ddf74deba41d55de3edc77c42a32af79bbea2c00bae7492264c60866ae5a").unwrap();
        let aad = Vec::from_hex("84932a55aac22b51e7b128d31d9f0550da28e6a3f394224707d878603386b2f9d0c6bcd8046679bfed7b68c517e7431e75d9dd34605727d2ef1c2babbf680ecc8d68d2c4886e9953a4034abde6da4189cd47c6bb3192242cf714d502ca6103ee84e08bc2ca4fd370d5ad4e7d06c7fbf496c6c7cc7eb19c40c61fb33df2a9ba48497a96c98d7b10c1f91098a6b7b16b4bab9687f27585ade1491ae0dba6a79e1e2d85dd9d9d45c5135ca5fca3f0f99a60ea39edbc9efc7923111c937913f225d67788d5f7e8852b697e26b92ec7bfcaa334a1665511c2b4c0a42d06f7ab98a9719516c8fd17f73804555ee84ab3b7d1762f6096b778d3cb9c799cbd49a9e4a325197b4e6cc4a5c4651f8b41ff88a92ec428354531f970263b467c77ed11312e2617d0d53fe9a8707f51f9f57a77bfb49afe3d89d85ec05ee17b9186f360c94ab8bb2926b65ca99dae1d6ee1af96cad09de70b6767e949023e4b380e66669914a741ed0fa420a48dbc7bfae5ef2019af36d1022283dd90655f25eec7151d471265d22a6d3f91dc700ba749bb67c0fe4bc0888593fbaf59d3c6fff1bf756a125910a63b9682b597c20f560ecb99c11a92c8c8c3f7fbfaa103146083a0ccaecf7a5f5e735a784a8820155914a289d57d8141870ffcaf588882332e0bcd8779efa931aa108dab6c3cce76691e345df4a91a03b71074d66333fd3591bff071ea099360f787bbe43b7b3dff2a59c41c7642eb79870222ad1c6f2e5a191ed5acea51134679587c9cf71c7d8ee290be6bf465c4ee47897a125708704ad610d8d00252d01959209d7cd04d5ecbbb1419a7e84037a55fefa13dee464b48a35c96bcb9a53e7ed461c3a1607ee00c3c302fd47cd73fda7493e947c9834a92d63dcfbd65aa7c38c3e3a2748bb5d9a58e7495d243d6b741078c8f7ee9c8813e473a323375702702b0afae1550c8341eedf5247627343a95240cb02e3e17d5dca16f8d8d3b2228e19c06399f8ec5c5e9dbe4caef6a0ea3ffb1d3c7eac03ae030e791fa12e537c80d56b55b764cadf27a8701052df1282ba8b5e3eb62b5dc7973ac40160e00722fa958d95102fc25c549d8c0e84bed95b7acb61ba65700c4de4feebf78d13b9682c52e937d23026fb4c6193e6644e2d3c99f91f4f39a8b9fc6d013f89c3793ef703987954dc0412b550652c01d922f525704d32d70d6d4079bc3551b563fb29577b3aecdc9505011701dddfd94830431e7a4918927ee44fb3831ce8c4513839e2deea1287f3fa1ab9b61a256c09637dbc7b4f0f8fbb783840f9c24526da883b0df0c473cf231656bd7bc1aaba7f321fec0971c8c2c3444bff2f55e1df7fea66ec3e440a612db9aa87bb505163a59e06b96d46f50d8120b92814ac5ab146bc78dbbf91065af26107815678ce6e33812e6bf3285d4ef3b7b04b076f21e7820dcbfdb4ad5218cf4ff6a65812d8fcb98ecc1e95e2fa58e3efe4ce26cd0bd400d6036ab2ad4f6c713082b5e3f1e04eb9e3b6c8f63f57953894b9e220e0130308e1fd91f72d398c1e7962ca2c31be83f31d6157633581a0a6910496de8d55d3d07090b6aa087159e388b7e7dec60f5d8a60d93ca2ae91296bd484d916bfaaa17c8f45ea4b1a91b37c82821199a2b7596672c37156d8701e7352aa48671d3b1bbbd2bd5f0a2268894a25b0cb2514af39c8743f8cce8ab4b523053739fd8a522222a09acf51ac704489cf17e4b7125455cb8f125b4d31af1eba1f8cf7f81a5a100a141a7ee72e8083e065616649c241f233645c5fc865d17f0285f5c52d9f45312c979bfb3ce5f2a1b951deddf280ffb3f370410cffd1583bfa90077835aa201a0712d1dcd1293ee177738b14e6b5e2a496d05220c3253bb6578d6aff774be91946a614dd7e879fb3dcf7451e0b9adb6a8c44f53c2c464bcc0019e9fad89cac7791a0a3f2974f759a9856351d4d2d7c5612c17cfc50f8479945df57716767b120a590f4bf656f4645029a525694d8a238446c5f5c2c1c995c09c1405b8b1eb9e0352ffdf766cc964f8dcf9f8f043dfab6d102cf4b298021abd78f1d9025fa1f8e1d710b38d9d1652f2d88d1305874ec41609b6617b65c5adb19b6295dc5c5da5fdf69f28144ea12f17c3c6fcce6b9b5157b3dfc969d6725fa5b098a4d9b1d31547ed4c9187452d281d0a5d456008caf1aa251fac8f950ca561982dc2dc908d3691ee3b6ad3ae3d22d002577264ca8e49c523bd51c4846be0d198ad9407bf6f7b82c79893eb2c05fe9981f687a97a4f01fe45ff8c8b7ecc551135cd960a0d6001ad35020be07ffb53cb9e731522ca8ae9364628914b9b8e8cc2f37f03393263603cc2b45295767eb0aac29b0930390eb89587ab2779d2e3decb8042acece725ba42eda650863f418f8d0d50d104e44fbbe5aa7389a4a144a8cecf00f45fb14c39112f9bfb56c0acbd44fa3ff261f5ce4acaa5134c2c1d0cca447040820c81ab1bcdc16aa075b7c68b10d06bbb7ce08b5b805e0238f24402cf24a4b4e00701935a0c68add3de090903f9b85b153cb179a582f57113bfc21c2093803f0cfa4d9d4672c2b05a24f7e4c34a8e9101b70303a7378b9c50b6cddd46814ef7fd73ef6923feceab8fc5aa8b0d185f2e83c7a99dcb1077c0ab5c1f5d5f01ba2f0420443f75c4417db9ebf1665efbb33dca224989920a64b44dc26f682cc77b4632c8454d49135e52503da855bc0f6ff8edc1145451a9772c06891f41064036b66c3119a0fc6e80dffeb65dc456108b7ca0296f4175fff3ed2b0f842cd46bd7e86f4c62dfaf1ddbf836263c00b34803de164983d0811cebfac86e7720c726d3048934c36c23189b02386a722ca9f0fe00233ab50db928d3bccea355cc681144b8b7edcaae4884d5a8f04425c0890ae2c74326e138066d8c05f4c82b29df99b034ea727afde590a1f2177ace3af99cfb1729d6539ce7f7f7314b046aab74497e63dd399e1f7d5f16517c23bd830d1fdee810f3c3b77573dd69c4b97d80d71fb5a632e00acdfa4f8e829faf3580d6a72c40b28a82172f8dcd4627663ebf6069736f21735fd84a226f427cd06bb055f94e7c92f31c48075a2955d82a5b9d2d0198ce0d4e131a112570a8ee40fb80462a81436a58e7db4e34b6e2c422e82f934ecda9949893da5730fc5c23c7c920f363f85ab28cc6a4206713c3152669b47efa8238fa826735f17b4e78750276162024ec85458cd5808e06f40dd9fd43775a456a3ff6cae90550d76d8b2899e0762ad9a371482b3e38083b1274708301d6346c22fea9bb4b73db490ff3ab05b2f7f9e187adef139a7794454b7300b8cc64d3ad76c0e4bc54e08833a4419251550655380d675bc91855aeb82585220bb97f03e976579c08f321b5f8f70988d3061f41465517d53ac571dbf1b24b94443d2e9a8e8a79b392b3d6a4ecdd7f626925c365ef6221305105ce9b5f5b6ecc5bed3d702bd4b7f5008aa8eb8c7aa3ade8ecf6251516fbefeea4e1082aa0e1848eddb31ffe44b04792d296054402826e4bd054e671f223e5557e4c94f89ca01c25c44f1a2ff2c05a70b43408250705e1b858bf0670679fdcd379203e36be3500dd981b1a6422c3cf15224f7fefdef0a5f225c5a09d15767598ecd9e262460bb33a4b5d09a64591efabc57c923d3be406979032ae0bc0997b65336a06dd75b253332ad6a8b63ef043f780a1b3fb6d0b6cad98b1ef4a02535eb39e14a866cfc5fc3a9c5deb2261300d71280ebe66a0776a151469551c3c5fa308757f956655278ec6330ae9e3625468c5f87e02cd9a6489910d4143c1f4ee13aa21a6859d907b788e28572fecee273d44e4a900fa0aa668dd861a60fb6b6b12c2c5ef3c8df1bd7ef5d4b0d1cdb8c15fffbb365b9784bd94abd001c6966216b9b67554ad7cb7f958b70092514f7800fc40244003e0fd1133a9b850fb17f4fcafde07fc87b07fb510670654a5d2d6fc9876ac74728ea41593beef003d6858786a52d3a40af7529596767c17000bfaf8dc52e871359f4ad8bf6e7b2853e5229bdf39657e213580294a5317c5df172865e1e17fe37093b585e04613f5f078f761b2b1752eb32983afda24b523af8851df9a02b37e77f543f18888a782a994a50563334282bf9cdfccc183fdf4fcd75ad86ee0d94f91ee2300a5befbccd14e03a77fc031a8cfe4f01e4c5290f5ac1da0d58ea054bd4837cfd93e5e34fc0eb16e48044ba76131f228d16cde9b0bb978ca7cdcd10653c358bdb26fdb723a530232c32ae0a4cecc06082f46e1c1d596bfe60621ad1e354e01e07b040cc7347c016653f44d926d13ca74e6cbc9d4ab4c99f4491c95c76fff5076b3936eb9d0a286b97c035ca88a3c6309f5febfd4cdaac869e4f58ed409b1e9eb4192fb2f9c2f12176d460fd98286c9d6df84598f260119fd29c63f800c07d8df83d5cc95f8c2fea2812e7890e8a0718bb1e031ecbebc0436dcf3e3b9a58bcc06b4c17f711f80fe1dffc3326a6eb6e00283055c6dabe20d311bfd5019591b7954f8163c9afad9ef8390a38f3582e0a79cdf0353de8eeb6b5f9f27b16ffdef7dd62869b4840ee226ccdce95e02c4545eb981b60571cd83f03dc5eaf8c97a0829a4318a9b3dc06c0e003db700b2260ff1fa8fee66890e637b109abb03ec901b05ca599775f48af50154c0e67d82bf0f558d7d3e0778dc38bea1eb5f74dc8d7f90abdf5511a424be66bf8b6a3cacb477d2e7ef4db68d2eba4d5289122d851f9501ba7e9c4957d8eba3be3fc8e785c4265a1d65c46f2809b70846c693864b169c9dcb78be26ea14b8613f145b01887222979a9e67aee5f800caa6f5c4229bdeefc901232ace6143c9865e4d9c07f51aa200afaf7e48a7d1d8faf366023beab12906ffcb3eaf72c0eb68075e4daf3c080e0c31911befc16f0cc4a09908bb7c1e26abab38bd7b788e1a09c0edf1a35a38d2ff1d3ed47fcdaae2f0934224694f5b56705b9409b6d3d64f3833b686f7576ec64bbdd6ff174e56c2d1edac0011f904681a73face26573fbba4e34652f7ae84acfb2fa5a5b3046f98178cd0831df7477de70e06a4c00e305f31aafc026ef064dd68fd3e4252b1b91d617b26c6d09b6891a00df68f105b5962e7f9d82da101dd595d286da721443b72b2aba2377f6e7772e33b3a5e3753da9c2578c5d1daab80187f55518c72a64ee150a7cb5649823c08c9f62cd7d020b45ec2cba8310db1a7785a46ab24785b4d54ff1660b5ca78e05a9a55edba9c60bf044737bc468101c4e8bd1480d749be5024adefca1d998abe33eaeb6b11fbb39da5d905fdd3f611b2e51517ccee4b8af72c2d948573505590d61a6783ab7278fc43fe55b1fcc0e7216444d3c8039bb8145ef1ce01c50e95a3f3feab0aee883fdb94cc13ee4d21c542aa795e18932228981690f4d4c57ca4db6eb5c092e29d8a05139d509a8aeb48baa1eb97a76e597a32b280b5e9d6c36859064c98ff96ef5126130264fa8d2f49213870d9fb036cff95da51f270311d9976208554e48ffd486470d0ecdb4e619ccbd8226147204baf8e235f54d8b1cba8fa34a9a4d055de515cdf180d2bb6739a175183c472e30b5c914d09eeb1b7dafd6872b38b48c6afc146101200e6e6a44fe5684e220adc11f5c403ddb15df8051e6bdef09117a3a5349938513776286473a3cf1d2788bb875052a2e6459fa7926da33380149c7f98d7700528a60c954e6f5ecb65842fde69d614be69eaa2040a4819ae6e756accf936e14c1e894489744a79c1f2c1eb295d13e2d767c09964b61f9cfe497649f712").unwrap();
        let auth = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, Some(&aad), PacketType::Genuine)
            .unwrap();
        let challenge = Vec::from_hex("8da7de6ea7bf2a81a396a42880ba1f5756734c4821309ac9aeffa2a26ce86873b9dc4935a772de6ec5162c6d075b14536800fb174841153511bfb597e992e2fe8a450c4bce102cc550bb37fd564c4d60bf884e").unwrap();
        assert_eq!(auth, challenge);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_4() {
        let alice =
            SecretKey::from_str("6c77432d1fda31e9f942f8af44607e10f3ad38a65f8a4bddae823e5eff90dc38")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("d2685070c1e6376e633e825296634fd461fa9e5bdf2109bcebd735e5a91f3e587c5cb782abb797fbf6bb5074fd1542a474f2a45b673763ec2db7fb99b737bbb9").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("56bd0c06f10352c3a1a9f4b4c92f6fa2b26df124b57878353c1fc691c51abea77c8817daeeb9fa546b77c8daf79d89b22b0e1b87574ece42371f00237aa9d83a").unwrap();
        let session_keys = get_shared_secrets(
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
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Responder);
        let contents: Vec<u8> = Vec::from_hex("7e0e78eb6990b059e6cf0ded66ea93ef82e72aa2f18ac24f2fc6ebab561ae557420729da103f64cecfa20527e15f9fb669a49bbbf274ef0389b3e43c8c44e5f60bf2ac38e2b55e7ec4273dba15ba41d21f8f5b3ee1688b3c29951218caf847a97fb50d75a86515d445699497d968164bf740012679b8962de573be941c62b7ef").unwrap();
        for _ in 0..223 {
            alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&Vec::new(), None, PacketType::Decoy)
                .unwrap();
        }
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Decoy)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("729847a3e9eba7a5bff454b5de3b393431ee360736b6c030d7a5bd01d1203d2e98f528543fd2bf886ccaa1ada5e215a730a36b3f4abfc4e252c89eb01d9512f94916dae8a76bf16e4da28986ffe159090fe5267ee3394300b7ccf4dfad389a26321b3a3423e4594a82ccfbad16d6561ecb8772b0cb040280ff999a29e3d9d4fd"),
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_5() {
        let alice =
            SecretKey::from_str("a6ec25127ca1aa4cf16b20084ba1e6516baae4d32422288e9b36d8bddd2de35a")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff053d7ecca53e33e185a8b9be4e7699a97c6ff4c795522e5918ab7cd6b6884f67e683f3dc").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7730be30000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex("00cf68f8f7ac49ffaa02c4864fdf6dfe7bbf2c740b88d98c50ebafe32c92f3427f57601ffcb21a3435979287db8fee6c302926741f9d5e464c647eeb9b7acaeda46e00abd7506fc9a719847e9a7328215801e96198dac141a15c7c2f68e0690dd1176292a0dded04d1f548aad88f1aebdc0a8f87da4bb22df32dd7c160c225b843e83f6525d6d484f502f16d923124fc538794e21da2eb689d18d87406ecced5b9f92137239ed1d37bcfa7836641a83cf5e0a1cf63f51b06f158e499a459ede41c").unwrap();
        for _ in 0..448 {
            alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&Vec::new(), None, PacketType::Genuine)
                .unwrap();
        }
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Genuine)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("77b4656934a82de1a593d8481f020194ddafd8cac441f9d72aeb8721e6a14f49698ca6d9b2b6d59d07a01aa552fd4d5b68d0d1617574c77dea10bfadbaa31b83885b7ceac2fd45e3e4a331c51a74e7b1698d81b64c87c73c5b9258b4d83297f9debc2e9aa07f8572ff434dc792b83ecf07b3197de8dc9cf7be56acb59c66cff5"),
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_6() {
        let alice =
            SecretKey::from_str("0af952659ed76f80f585966b95ab6e6fd68654672827878684c8b547b1b94f5a")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc81017fd92fd31637c26c906b42092e11cc0d3afae8d9019d2578af22735ce7bc469c72d").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("9652d78baefc028cd37a6a92625b8b8f85fde1e4c944ad3f20e198bef8c02f19fffffffffffffffffffffffffffffffffffffffffffffffffffffffff2e91870").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_bob,
            elliswift_alice,
            alice,
            ElligatorSwiftParty::B,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Responder);
        let contents = Vec::from_hex(
            "5c6272ee55da855bbbf7b1246d9885aa7aa601a715ab86fa46c50da533badf82b97597c968293ae04e"
                .repeat(97561)
                .as_str(),
        )
        .unwrap();
        for _ in 0..673 {
            alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&Vec::new(), None, PacketType::Genuine)
                .unwrap();
        }
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Genuine)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("657a4a19711ce593c3844cb391b224f60124aba7e04266233bc50cafb971e26c7716b76e98376448f7d214dd11e629ef9a974d60e3770a695810a61c4ba66d78b936ee7892b98f0b48ddae9fcd8b599dca1c9b43e9b95e0226cf8d4459b8a7c2c4e6db80f1d58c7b20dd7208fa5c1057fb78734223ee801dbd851db601fee61e"),
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_vector_7() {
        let alice =
            SecretKey::from_str("f90e080c64b05824c5a24b2501d5aeaf08af3872ee860aa80bdcd430f7b63494")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff115173765dc202cf029ad3f15479735d57697af12b0131dd21430d5772e4ef11474d58b9").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("12a50f3fafea7c1eeada4cf8d33777704b77361453afc83bda91eef349ae044d20126c6200547ea5a6911776c05dee2a7f1a9ba7dfbabbbd273c3ef29ef46e46").unwrap();
        let session_keys = get_shared_secrets(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            Network::Bitcoin,
        )
        .unwrap();
        let mut alice_packet_handler = PacketHandler::new(session_keys.clone(), Role::Initiator);
        let contents = Vec::from_hex(
            "5f67d15d22ca9b2804eeab0a66f7f8e3a10fa5de5809a046084348cbc5304e843ef96f59a59c7d7fdfe5946489f3ea297d941bac326225df316a25fc90f0e65b0d31a9c497e960fdbf8c482516bc8a9c1c77b7f6d0e1143810c737f76f9224e6f2c9af5186b4f7259c7e8d165b6e4fe3d38a60bdbdd4d06ecdcaaf62086070dbb68686b802d53dfd7db14b18743832605f5461ad81e2af4b7e8ff0eff0867a25b93cec7becf15c43131895fed09a83bf1ee4a87d44dd0f02a837bf5a1232e201cb882734eb9643dc2dc4d4e8b5690840766212c7ac8f38ad8a9ec47c7a9b3e022ae3eb6a32522128b518bd0d0085dd81c5"
                .repeat(69615)
                .as_str(),
        )
        .unwrap();
        for _ in 0..1024 {
            alice_packet_handler
                .packet_writer
                .encrypt_packet_with_alloc(&Vec::new(), None, PacketType::Genuine)
                .unwrap();
        }
        let enc = alice_packet_handler
            .packet_writer
            .encrypt_packet_with_alloc(&contents, None, PacketType::Decoy)
            .unwrap();
        assert!(
            enc.to_lower_hex_string().ends_with("7c4b9e1e6c1ce69da7b01513cdc4588fd93b04dafefaf87f31561763d906c672bac3dfceb751ebd126728ac017d4d580e931b8e5c7d5dfe0123be4dc9b2d2238b655c8a7fadaf8082c31e310909b5b731efc12f0a56e849eae6bfeedcc86dd27ef9b91d159256aa8e8d2b71a311f73350863d70f18d0d7302cf551e4303c7733"),
        );
    }
}
