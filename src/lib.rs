//! BIP 324 encrypted transport for exchanging Bitcoin P2P messages. Read more about the [specification](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
//!
//! # Use case
//!
//! 1. Client-server applications that transmit and receive Bitcoin P2P messages and would like increased privacy.
//!
//! # Example
//! ```rust
//! use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, receive_v2_handshake, responder_complete_v2_handshake};
//! // Alice starts a connection with Bob by making a pub/priv keypair and sending a message to Bob.
//! let handshake_init = initialize_v2_handshake(None).unwrap();
//!
//! // Bob parses Alice's message, generates his pub/priv key, and sends a message back.
//! let mut bob_handshake = receive_v2_handshake(handshake_init.message.clone()).unwrap();
//!
//! // Alice finishes her handshake by using her keys from earlier, and sending a final message to Bob.
//! let alice_completion = initiator_complete_v2_handshake(bob_handshake.message.clone(), handshake_init).unwrap();
//!
//! // Bob checks Alice derived the correct keys for the session by authenticating her first message.
//! let _bob_completion = responder_complete_v2_handshake(alice_completion.message.clone(), &mut bob_handshake).unwrap();
//!
//! // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
//! let mut alice = alice_completion.packet_handler;
//! let mut bob = bob_handshake.packet_handler;
//!
//! let message = b"Hello world".to_vec();
//! let encrypted_message_to_alice = bob.prepare_v2_packet(message.clone(), None, false).unwrap();
//! let messages = alice.receive_v2_packets(encrypted_message_to_alice, None).unwrap();
//! let secret_message = messages.first().unwrap().message.clone().unwrap();
//! assert_eq!(message, secret_message);
//!
//! let message = b"Goodbye!".to_vec();
//! let encrypted_message_to_bob = alice.prepare_v2_packet(message.clone(), None, false).unwrap();
//! let messages = bob.receive_v2_packets(encrypted_message_to_bob, None).unwrap();
//! let secret_message = messages.first().unwrap().message.clone().unwrap();
//! assert_eq!(message, secret_message);
//! ```

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

mod chacha;
mod chachapoly;
mod error;
mod hkdf;
mod poly1305;
mod types;

use alloc::vec;
use chacha::ChaCha20;
use chachapoly::ChaCha20Poly1305;
use error::FSChaChaError;
pub use error::{HandshakeCompletionError, ResponderHandshakeError};
use hkdf::Hkdf;
use rand::Rng;
use secp256k1::{
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    ffi::types::AlignedType,
    PublicKey, Secp256k1, SecretKey,
};
pub use types::SessionKeyMaterial;
pub use types::{
    CompleteHandshake, EcdhPoint, HandshakeRole, InitiatorHandshake, ReceivedMessage,
    ResponderHandshake,
};

const MAX_GARBAGE_LEN: u32 = 4095;
const REKEY_INTERVAL: u32 = 224;
const LENGTH_FIELD_LEN: usize = 3;
const CHACHA_BLOCKS_USED: u32 = 3;
const DECOY: u8 = 128;
const REKEY_INITIAL_NONCE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
const NETWORK_MAGIC: &[u8] = &[0xf9, 0xbe, 0xb4, 0xd9];

/// Encrypt and decrypt messages with a peer.
#[derive(Clone, Debug)]
pub struct PacketHandler {
    /// The unique identifier of your communication channel.
    pub session_id: [u8; 32],
    /// Your role in the handshake.
    pub role: HandshakeRole,
    length_encoding_cipher: FSChaCha20,
    length_decoding_cipher: FSChaCha20,
    packet_encoding_cipher: FSChaCha20Poly1305,
    packet_decoding_cipher: FSChaCha20Poly1305,
}

impl PacketHandler {
    fn new(session_keys: SessionKeyMaterial, role: HandshakeRole) -> Self {
        match role {
            HandshakeRole::Initiator => {
                let length_encoding_cipher = FSChaCha20::new(session_keys.initiator_length_key);
                let length_decoding_cipher = FSChaCha20::new(session_keys.responder_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(session_keys.initiator_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(session_keys.responder_packet_key);
                PacketHandler {
                    session_id: session_keys.session_id,
                    role,
                    length_encoding_cipher,
                    length_decoding_cipher,
                    packet_encoding_cipher,
                    packet_decoding_cipher,
                }
            }
            HandshakeRole::Responder => {
                let length_encoding_cipher = FSChaCha20::new(session_keys.responder_length_key);
                let length_decoding_cipher = FSChaCha20::new(session_keys.initiator_length_key);
                let packet_encoding_cipher =
                    FSChaCha20Poly1305::new(session_keys.responder_packet_key);
                let packet_decoding_cipher =
                    FSChaCha20Poly1305::new(session_keys.initiator_packet_key);
                PacketHandler {
                    session_id: session_keys.session_id,
                    role,
                    length_encoding_cipher,
                    length_decoding_cipher,
                    packet_encoding_cipher,
                    packet_decoding_cipher,
                }
            }
        }
    }

    /// Prepare a vector of bytes to be encrypted and sent over the wire.
    ///
    /// # Arguments
    ///
    /// `contents` - The Bitcoin P2P protocol message to send.
    ///
    /// `aad` - Optional authentication for the peer, currently only used for the first round of messages.
    ///
    /// `decoy` - Should the peer ignore this message.
    ///
    /// # Returns
    ///
    /// A ciphertext to send over the wire.
    ///
    /// # Errors
    ///
    /// Fails if the packet was not encrypted properly.
    pub fn prepare_v2_packet(
        &mut self,
        contents: Vec<u8>,
        aad: Option<Vec<u8>>,
        decoy: bool,
    ) -> Result<Vec<u8>, FSChaChaError> {
        let mut packet: Vec<u8> = Vec::new();
        let mut header: u8 = 0;
        if decoy {
            header = DECOY;
        }
        let content_len = (contents.len() as u32).to_le_bytes()[0..LENGTH_FIELD_LEN].to_vec();
        let mut plaintext = vec![header];
        plaintext.extend(contents);
        let auth = aad.unwrap_or_default();
        let enc_len = self.length_encoding_cipher.crypt(content_len);
        let enc_packet = self.packet_encoding_cipher.encrypt(auth, plaintext)?;
        packet.extend(enc_len);
        packet.extend(enc_packet);
        Ok(packet)
    }

    /// Decrypt the one or more messages from bytes received by a V2 peer.
    ///
    /// # Arguments
    ///
    /// `ciphertext` - The entire message received from the peer.
    ///
    /// `aad` - Optional authentication from the peer, currently only used for the first round of messages.
    ///
    /// # Returns
    ///
    /// A vector of messages from the peer.
    ///
    /// # Errors
    ///
    /// Fails if the packet was not decrypted or authenticated properly.  
    pub fn receive_v2_packets(
        &mut self,
        ciphertext: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<ReceivedMessage>, FSChaChaError> {
        let auth = aad.unwrap_or_default();
        let mut messages: Vec<ReceivedMessage> = Vec::new();
        let mut start_index: Option<usize> = Some(0);
        while start_index.is_some() {
            let (message, index) =
                self.decode_packet_from_len(&ciphertext, &auth, start_index.unwrap())?;
            start_index = index;
            messages.push(ReceivedMessage { message })
        }
        Ok(messages)
    }

    pub fn decypt_len(&mut self, len_slice: [u8; 3]) -> Result<usize, FSChaChaError> {
        let mut enc_content_len = self.length_decoding_cipher.crypt(len_slice.to_vec());
        enc_content_len.push(0u8);
        let content_slice: [u8; 4] = enc_content_len
            .try_into()
            .expect("Length of slice should be 4.");
        let content_len = u32::from_le_bytes(content_slice);
        Ok(content_len as usize + 17)
    }

    pub fn decrypt_contents(
        &mut self,
        contents: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> Result<ReceivedMessage, FSChaChaError> {
        let auth = aad.unwrap_or_default();
        let plaintext = self.packet_decoding_cipher.decrypt(auth, contents)?;
        let header = *plaintext
            .first()
            .expect("All contents should include a header.");
        if header.eq(&DECOY) {
            return Ok(ReceivedMessage { message: None });
        }
        let message = plaintext[1..].to_vec();
        Ok(ReceivedMessage {
            message: Some(message),
        })
    }

    fn decode_packet_from_len(
        &mut self,
        ciphertext: &[u8],
        auth: &[u8],
        start_index: usize,
    ) -> Result<(Option<Vec<u8>>, Option<usize>), FSChaChaError> {
        let enc_content_len = ciphertext[start_index..LENGTH_FIELD_LEN + start_index].to_vec();
        let mut content_len = self.length_decoding_cipher.crypt(enc_content_len);
        content_len.push(0u8);
        let content_slice: [u8; 4] = content_len
            .try_into()
            .expect("Length of slice should be 4.");
        let content_len = u32::from_le_bytes(content_slice);
        let aead_len = 1 + content_len + 16;
        let mut next_content: Option<usize> = None;
        if aead_len > ciphertext.len() as u32 {
            return Err(FSChaChaError::StreamDecryption(
                "Failed to decrypt length bytes properly.".to_string(),
            ));
        }
        if start_index as u32 + aead_len + 3 < ciphertext.len() as u32 {
            next_content = Some((start_index as u32 + aead_len + 3) as usize);
        }
        let aead = ciphertext[start_index + 3..start_index + (aead_len as usize) + 3].to_vec();
        let plaintext = self.packet_decoding_cipher.decrypt(auth.to_vec(), aead)?;
        let header = *plaintext
            .first()
            .expect("All contents should include a header.");
        if header.eq(&DECOY) {
            return Ok((None, next_content));
        }
        let message = plaintext[1..].to_vec();
        Ok((Some(message), next_content))
    }
}

enum CryptType {
    Encrypt,
    Decrypt,
}

/// A wrapper over ChaCha20Poly1305 AEAD stream cipher which handles automatically changing
/// nonces and re-keying.
///
/// FSChaCha20Poly1305 is used for message packets in BIP324.
#[derive(Clone, Debug)]
struct FSChaCha20Poly1305 {
    key: [u8; 32],
    message_counter: u32,
}

impl FSChaCha20Poly1305 {
    fn new(key: [u8; 32]) -> Self {
        FSChaCha20Poly1305 {
            key,
            message_counter: 0,
        }
    }

    fn crypt(
        &mut self,
        aad: Vec<u8>,
        mut contents: Vec<u8>,
        crypt_type: CryptType,
    ) -> Result<Vec<u8>, FSChaChaError> {
        let mut counter_div = (self.message_counter / REKEY_INTERVAL)
            .to_le_bytes()
            .to_vec();
        counter_div.extend([0u8; 4]); // ok? invalid for 4 billion messages
        let counter_mod = (self.message_counter % REKEY_INTERVAL).to_le_bytes();
        let mut nonce = counter_mod.to_vec();
        nonce.extend(counter_div); // mod slice then div slice
        let cipher =
            ChaCha20Poly1305::new(self.key, nonce.try_into().expect("Nonce is malformed."));
        let converted_ciphertext: Vec<u8> = match crypt_type {
            CryptType::Encrypt => {
                let mut buffer = contents.clone();
                buffer.extend([0u8; 16]);
                cipher
                    .encrypt(&mut contents, Some(&aad), &mut buffer)
                    .map_err(|e| FSChaChaError::Poly1305Encryption(e.to_string()))?;
                buffer.to_vec()
            }
            CryptType::Decrypt => {
                let mut ciphertext = contents.clone();
                cipher
                    .decrypt(&mut ciphertext, Some(&aad))
                    .map_err(|e| FSChaChaError::Poly1305Decryption(e.to_string()))?;
                ciphertext[..ciphertext.len() - 16].to_vec()
            }
        };
        if (self.message_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = REKEY_INITIAL_NONCE.to_vec();
            let mut counter_div = (self.message_counter / REKEY_INTERVAL)
                .to_le_bytes()
                .to_vec();
            counter_div.extend([0u8; 4]);
            let counter_mod = (self.message_counter % REKEY_INTERVAL).to_le_bytes();
            let mut nonce = counter_mod.to_vec();
            nonce.extend(counter_div);
            rekey_nonce.extend(nonce[4..].to_vec());
            let mut buffer = [0u8; 48];
            let mut plaintext = [0u8; 32];
            let cipher = ChaCha20Poly1305::new(
                self.key,
                rekey_nonce.try_into().expect("Nonce is malformed."),
            );
            cipher
                .encrypt(&mut plaintext, Some(&aad), &mut buffer)
                .map_err(|e| FSChaChaError::Poly1305Encryption(e.to_string()))?;
            self.key = buffer[0..32]
                .try_into()
                .expect("Cipher should be at least 32 bytes.");
        }
        self.message_counter += 1;
        Ok(converted_ciphertext)
    }

    pub fn encrypt(&mut self, aad: Vec<u8>, contents: Vec<u8>) -> Result<Vec<u8>, FSChaChaError> {
        self.crypt(aad, contents, CryptType::Encrypt)
    }

    pub fn decrypt(&mut self, aad: Vec<u8>, contents: Vec<u8>) -> Result<Vec<u8>, FSChaChaError> {
        self.crypt(aad, contents, CryptType::Decrypt)
    }
}

/// A wrapper over ChaCha20 (unauthenticated) stream cipher which handles automatically changing
/// nonces and re-keying.
///
/// FSChaCha20 is used for lengths in BIP324. Should be noted that the lengths are still
/// implicitly authenticated by the message packets.
#[derive(Clone, Debug)]
struct FSChaCha20 {
    key: [u8; 32],
    block_counter: u32,
    chunk_counter: u32,
}

impl FSChaCha20 {
    fn new(key: [u8; 32]) -> Self {
        FSChaCha20 {
            key,
            block_counter: 0,
            chunk_counter: 0,
        }
    }

    fn crypt(&mut self, chunk: Vec<u8>) -> Vec<u8> {
        let zeroes = (0u32).to_le_bytes().to_vec();
        let counter_mod = (self.chunk_counter / REKEY_INTERVAL).to_le_bytes();
        let mut nonce = zeroes.clone();
        nonce.extend(counter_mod);
        nonce.extend(zeroes);
        let mut cipher = ChaCha20::new(self.key, nonce.try_into().expect("Nonce is malformed."), 0);
        let mut buffer = chunk.clone();
        cipher.seek(self.block_counter);
        cipher.apply_keystream(&mut buffer);
        self.block_counter += CHACHA_BLOCKS_USED;
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            let mut key_buffer = [0u8; 32];
            cipher.seek(self.block_counter);
            cipher.apply_keystream(&mut key_buffer);
            self.block_counter = 0;
            self.key = key_buffer;
        }
        self.chunk_counter += 1;
        buffer
    }
}

fn gen_key(rng: &mut impl Rng) -> Result<SecretKey, secp256k1::Error> {
    let mut buffer: Vec<u8> = vec![0; 32];
    rng.fill(&mut buffer[..]);
    let sk = SecretKey::from_slice(&buffer)?;
    Ok(sk)
}

fn new_elligator_swift(sk: SecretKey) -> ElligatorSwift {
    let mut buf_ful = vec![AlignedType::zeroed(); Secp256k1::preallocate_size()];
    let curve = Secp256k1::preallocated_new(&mut buf_ful).unwrap();
    let pk = PublicKey::from_secret_key(&curve, &sk);
    ElligatorSwift::from_pubkey(pk)
}

fn gen_garbage(garbage_len: u32, rng: &mut impl Rng) -> Vec<u8> {
    let buffer: Vec<u8> = (0..garbage_len).map(|_| rng.gen()).collect();
    buffer
}

fn get_shared_secrets(
    a: ElligatorSwift,
    b: ElligatorSwift,
    secret: SecretKey,
    party: ElligatorSwiftParty,
) -> SessionKeyMaterial {
    let data = "bip324_ellswift_xonly_ecdh".as_bytes();
    let ecdh_sk = ElligatorSwift::shared_secret(a, b, secret, party, Some(data));
    initialize_session_key_material(ecdh_sk.as_secret_bytes())
}

fn initialize_session_key_material(ikm: &[u8]) -> SessionKeyMaterial {
    let ikm_salt = "bitcoin_v2_shared_secret".as_bytes();
    let magic = NETWORK_MAGIC;
    let salt = [ikm_salt, magic].concat();
    let hk = Hkdf::extract(salt.as_slice(), ikm);
    let mut session_id = [0u8; 32];
    let session_info = "session_id".as_bytes();
    hk.expand(session_info, &mut session_id)
        .expect("32 is a valid buffer length.");
    let mut initiator_length_key = [0u8; 32];
    let intiiator_l_info = "initiator_L".as_bytes();
    hk.expand(intiiator_l_info, &mut initiator_length_key)
        .expect("32 is a valid buffer length.");
    let mut initiator_packet_key = [0u8; 32];
    let intiiator_p_info = "initiator_P".as_bytes();
    hk.expand(intiiator_p_info, &mut initiator_packet_key)
        .expect("32 is a valid buffer length.");
    let mut responder_length_key = [0u8; 32];
    let responder_l_info = "responder_L".as_bytes();
    hk.expand(responder_l_info, &mut responder_length_key)
        .expect("32 is a valid buffer length.");
    let mut responder_packet_key = [0u8; 32];
    let responder_p_info = "responder_P".as_bytes();
    hk.expand(responder_p_info, &mut responder_packet_key)
        .expect("32 is a valid buffer length.");
    let mut garbage = [0u8; 32];
    let garbage_info = "garbage_terminators".as_bytes();
    hk.expand(garbage_info, &mut garbage)
        .expect("32 is a valid buffer length.");
    let initiator_garbage_terminator: [u8; 16] =
        garbage[..16].try_into().expect("Half of 32 is 16.");
    let responder_garbage_terminator: [u8; 16] =
        garbage[16..].try_into().expect("Half of 32 is 16.");
    SessionKeyMaterial {
        session_id,
        initiator_length_key,
        initiator_packet_key,
        responder_length_key,
        responder_packet_key,
        initiator_garbage_terminator,
        responder_garbage_terminator,
    }
}

/// Initialize a V2 transport handshake with a peer. The `InitiatorHandshake` contains a message ready to be sent over the wire,
/// and the information necessary for completing ECDH when the peer responds.
///
/// # Arguments
///
/// `garbage_len` - The length of the additional garbage to be sent along with the encoded public key.
///
/// # Returns
///
/// A partial handshake.
///
/// # Errors
///
/// Fails if their was an error generating the keypair.
#[cfg(feature = "std")]
pub fn initialize_v2_handshake(
    garbage_len: Option<u32>,
) -> Result<InitiatorHandshake, secp256k1::Error> {
    let mut rng = rand::thread_rng();
    initialize_v2_handshake_with_rng(garbage_len, &mut rng)
}

/// Initialize a V2 transport handshake with a peer. The `InitiatorHandshake` contains a message ready to be sent over the wire,
/// and the information necessary for completing ECDH when the peer responds.
///
/// # Arguments
///
/// `garbage_len` - The length of the additional garbage to be sent along with the encoded public key.
/// `rng` - supplied Random Number Generator.
///
/// # Returns
///
/// A partial handshake.
///
/// # Errors
///
/// Fails if their was an error generating the keypair.
pub fn initialize_v2_handshake_with_rng(
    garbage_len: Option<u32>,
    rng: &mut impl Rng,
) -> Result<InitiatorHandshake, secp256k1::Error> {
    let sk = gen_key(rng)?;
    let es = new_elligator_swift(sk);
    let garbage_len = garbage_len.unwrap_or(MAX_GARBAGE_LEN);
    let garbage = gen_garbage(garbage_len, rng);
    let point = EcdhPoint {
        secret_key: sk,
        elligator_swift: es,
    };
    let mut message = es.to_array().to_vec();
    message.extend_from_slice(&garbage);
    Ok(InitiatorHandshake {
        message,
        point,
        garbage,
    })
}

/// Receive a V2 handshake over the wire. The `ResponderHandshake` contains the message ready to be sent over the wire and a struct for parsing packets.
///
/// # Arguments
///
/// `message` - The message received over the wire.
///
/// # Returns
///
/// A completed handshake containing a `PacketHandler`.
///
/// # Errors
///
/// Fails if the packet was not prepared properly.
#[cfg(feature = "std")]
pub fn receive_v2_handshake(
    message: Vec<u8>,
) -> Result<ResponderHandshake, ResponderHandshakeError> {
    let mut rng = rand::thread_rng();
    receive_v2_handshake_with_rng(message, &mut rng)
}

/// Receive a V2 handshake over the wire. The `ResponderHandshake` contains the message ready to be sent over the wire and a struct for parsing packets.
///
/// # Arguments
///
/// `message` - The message received over the wire.
/// `rng` - Supplied Random Number Generator.
///
/// # Returns
///
/// A completed handshake containing a `PacketHandler`.
///
/// # Errors
///
/// Fails if the packet was not prepared properly.
pub fn receive_v2_handshake_with_rng(
    message: Vec<u8>,
    rng: &mut impl Rng,
) -> Result<ResponderHandshake, ResponderHandshakeError> {
    let mut network_magic = NETWORK_MAGIC.to_vec();
    let mut version_bytes = "version".as_bytes().to_vec();
    version_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    network_magic.extend(version_bytes);

    if message.starts_with(&network_magic) {
        Err(ResponderHandshakeError::IncorrectMessage(
            "Cannot respond to V1 message.".to_string(),
        ))
    } else {
        let mut response: Vec<u8> = Vec::new();
        let sk = gen_key(rng).map_err(ResponderHandshakeError::ECC)?;
        let es = new_elligator_swift(sk);
        response.extend(&es.to_array());
        let elliswift_message = &message[..64];
        let elliswift_slice: Result<[u8; 64], _> = elliswift_message.try_into();
        let their_elliswift = elliswift_slice
            .map_err(|e| ResponderHandshakeError::IncorrectMessage(e.to_string()))?;
        let theirs = ElligatorSwift::from_array(their_elliswift);
        let session_keys = get_shared_secrets(theirs, es, sk, ElligatorSwiftParty::B);
        let initiator_garbage = message[64..].to_vec();
        let initiator_garbage_len = initiator_garbage.len() as u32;
        let response_garbage = gen_garbage(initiator_garbage_len, rng);
        if initiator_garbage_len > MAX_GARBAGE_LEN {
            return Err(ResponderHandshakeError::IncorrectMessage(
                "Garbage length is too large.".to_string(),
            ));
        }
        response.extend(response_garbage.clone());
        response.extend(session_keys.responder_garbage_terminator);
        let mut packet_handler = PacketHandler::new(session_keys.clone(), HandshakeRole::Responder);
        let garbage_auth = packet_handler
            .prepare_v2_packet(Vec::new(), Some(response_garbage), false)
            .map_err(|e| ResponderHandshakeError::EncryptionError(e.to_string()))?;
        response.extend(garbage_auth);
        Ok(ResponderHandshake {
            message: response,
            session_keys,
            packet_handler,
            initiator_garbage,
        })
    }
}

/// Receive a message from the responder and complete the V2 handshake.
///
/// # Arguments
///
/// `message` - The message received over the wire.
///
/// `responder_handshake` - The result of the initial handshake.
///
/// # Returns
///
/// A completed handshake containing a `PacketHandler`.
///
/// # Errors
///
/// Fails if the packet was not decrypted or authenticated properly.
pub fn initiator_complete_v2_handshake(
    message: Vec<u8>,
    init_handshake: InitiatorHandshake,
) -> Result<CompleteHandshake, HandshakeCompletionError> {
    let elliswift_message = &message[..64];
    let elliswift_slice: Result<[u8; 64], _> = elliswift_message.try_into();
    let their_elliswift =
        elliswift_slice.map_err(|e| HandshakeCompletionError::MessageTooShort(e.to_string()))?;
    let theirs = ElligatorSwift::from_array(their_elliswift);
    let session_keys = get_shared_secrets(
        init_handshake.point.elligator_swift,
        theirs,
        init_handshake.point.secret_key,
        ElligatorSwiftParty::A,
    );
    let mut packet_handler = PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
    let their_garbge_term = session_keys.responder_garbage_terminator;
    let garbage_aad = split_completion_message(message[64..].to_vec(), their_garbge_term);
    match garbage_aad {
        Some((garbage, contents)) => {
            packet_handler
                .receive_v2_packets(contents, Some(garbage))
                .map_err(|e| HandshakeCompletionError::DecryptionError(e.to_string()))?;
            let garbage_term = session_keys.initiator_garbage_terminator.to_vec();
            let mut response: Vec<u8> = Vec::new();
            response.extend(garbage_term);
            let auth = packet_handler
                .prepare_v2_packet(Vec::new(), Some(init_handshake.garbage), false)
                .map_err(|e| HandshakeCompletionError::DecryptionError(e.to_string()))?;
            response.extend(&auth);
            let handshake = CompleteHandshake {
                message: response,
                packet_handler,
            };
            Ok(handshake)
        }
        None => Err(HandshakeCompletionError::NoTerminator(
            "The garbage terminator was not found in the response message.".to_string(),
        )),
    }
}

/// Receive a message from the initiator and complete the handshake or disconnect.
///
/// # Arguments
///
/// `message` - The message received over the wire.
///
/// `responder_handshake` - A mutuable reference to the result of the initial handshake response.
///
/// # Returns
///
/// Void if the handshake was successful.
///
/// # Errors
///
/// Fails if the packet was not decrypted or authenticated properly.
pub fn responder_complete_v2_handshake(
    message: Vec<u8>,
    responder_handshake: &mut ResponderHandshake,
) -> Result<(), HandshakeCompletionError> {
    let garbage_term = message[..16].to_vec();
    if garbage_term.ne(&responder_handshake
        .session_keys
        .initiator_garbage_terminator
        .to_vec())
    {
        return Err(HandshakeCompletionError::NoTerminator(
            "Garbage terminator does not match.".to_string(),
        ));
    }
    let garbage_auth = message[16..].to_vec();
    responder_handshake
        .packet_handler
        .receive_v2_packets(
            garbage_auth,
            Some(responder_handshake.initiator_garbage.clone()),
        )
        .map_err(|e| HandshakeCompletionError::DecryptionError(e.to_string()))?;
    Ok(())
}

fn split_completion_message(
    message: Vec<u8>,
    garbage_term: [u8; 16],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if let Some(index) = message
        .windows(garbage_term.len())
        .position(|window| window == garbage_term)
    {
        let before = message[..index].to_vec();
        let after = message[(index + garbage_term.len())..].to_vec();
        Some((before, after))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_sec_keygen() {
        let mut rng = rand::thread_rng();
        gen_key(&mut rng).unwrap();
    }

    #[test]
    fn test_initial_message() {
        let handshake_init = initialize_v2_handshake(None).unwrap();
        let message = hex::encode(&handshake_init.message);
        let es = handshake_init.point.elligator_swift.to_string();
        assert!(message.contains(&es))
    }

    #[test]
    fn test_message_response() {
        let handshake_init = initialize_v2_handshake(None).unwrap();
        receive_v2_handshake(handshake_init.message).unwrap();
    }

    #[test]
    fn test_expand_extract() {
        let ikm = hex::decode("c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592")
            .unwrap();
        let session_keys = initialize_session_key_material(&ikm);
        assert_eq!(
            hex::encode(session_keys.session_id),
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
        );
        assert_eq!(
            "9a6478b5fbab1f4dd2f78994b774c03211c78312786e602da75a0d1767fb55cf",
            hex::encode(session_keys.initiator_length_key)
        );
        assert_eq!(
            "7d0c7820ba6a4d29ce40baf2caa6035e04f1e1cefd59f3e7e59e9e5af84f1f51",
            hex::encode(session_keys.initiator_packet_key)
        );
        assert_eq!(
            "17bc726421e4054ac6a1d54915085aaa766f4d3cf67bbd168e6080eac289d15e",
            hex::encode(session_keys.responder_length_key)
        );
        assert_eq!(
            "9f0fc1c0e85fd9a8eee07e6fc41dba2ff54c7729068a239ac97c37c524cca1c0",
            hex::encode(session_keys.responder_packet_key)
        );
        assert_eq!(
            "faef555dfcdb936425d84aba524758f3",
            hex::encode(session_keys.initiator_garbage_terminator)
        );
        assert_eq!(
            "02cb8ff24307a6e27de3b4e7ea3fa65b",
            hex::encode(session_keys.responder_garbage_terminator)
        );
    }

    #[test]
    fn test_handshake_session_id() {
        let handshake_init = initialize_v2_handshake(Some(0)).unwrap();
        let handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
        let handshake_completion =
            initiator_complete_v2_handshake(handshake_response.message, handshake_init).unwrap();
        let sid = handshake_completion.packet_handler.session_id;
        let sid2 = handshake_response.packet_handler.session_id;
        assert_eq!(sid, sid2);
    }

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        let message = b"Bitcoin rox!".to_vec();
        let enc_packet = alice_packet_handler
            .prepare_v2_packet(message.clone(), None, true)
            .unwrap();
        let dec = bob_packet_handler
            .receive_v2_packets(enc_packet, None)
            .unwrap();
        let secret_message = dec.first().unwrap().message.clone();
        assert_eq!(None, secret_message);
        let message = b"Windows sox!".to_vec();
        let enc_packet = bob_packet_handler
            .prepare_v2_packet(message.clone(), None, false)
            .unwrap();
        let dec = alice_packet_handler
            .receive_v2_packets(enc_packet, None)
            .unwrap();
        let secret_message = dec.first().unwrap().message.clone();
        assert_eq!(message, secret_message.unwrap());
    }

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        for _ in 0..REKEY_INTERVAL + 100 {
            let message = gen_garbage(4095, &mut rng);
            let enc_packet = alice_packet_handler
                .prepare_v2_packet(message.clone(), None, false)
                .unwrap();
            let dec_packet = bob_packet_handler
                .receive_v2_packets(enc_packet, None)
                .unwrap();
            let secret_message = dec_packet.first().unwrap().message.clone().unwrap();
            assert_eq!(message, secret_message);
            let message = gen_garbage(420, &mut rng);
            let enc_packet = bob_packet_handler
                .prepare_v2_packet(message.clone(), None, false)
                .unwrap();
            let dec_packet = alice_packet_handler
                .receive_v2_packets(enc_packet, None)
                .unwrap();
            let secret_message = dec_packet.first().unwrap().message.clone().unwrap();
            assert_eq!(message, secret_message);
        }
    }

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        let auth_garbage = gen_garbage(200, &mut rng);
        let enc_packet = alice_packet_handler
            .prepare_v2_packet(Vec::new(), Some(auth_garbage.clone()), false)
            .unwrap();
        let _ = bob_packet_handler
            .receive_v2_packets(enc_packet, Some(auth_garbage))
            .unwrap();
    }

    #[test]
    fn test_full_handshake() {
        let handshake_init = initialize_v2_handshake(None).unwrap();
        let mut handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
        let alice_completion =
            initiator_complete_v2_handshake(handshake_response.message.clone(), handshake_init)
                .unwrap();
        let _bob_completion = responder_complete_v2_handshake(
            alice_completion.message.clone(),
            &mut handshake_response,
        )
        .unwrap();
        let mut alice = alice_completion.packet_handler;
        let mut bob = handshake_response.packet_handler;
        let message = b"Hello world".to_vec();
        let encrypted_message_to_alice =
            bob.prepare_v2_packet(message.clone(), None, false).unwrap();
        let dec = alice
            .receive_v2_packets(encrypted_message_to_alice, None)
            .unwrap();
        let secret_message = dec.first().unwrap().message.clone();
        assert_eq!(message, secret_message.unwrap());
        let message = b"g!".to_vec();
        let encrypted_message_to_bob = alice
            .prepare_v2_packet(message.clone(), None, false)
            .unwrap();
        let dec = bob
            .receive_v2_packets(encrypted_message_to_bob, None)
            .unwrap();
        let secret_message = dec.first().unwrap().message.clone();
        assert_eq!(message, secret_message.unwrap());
    }

    #[test]
    fn test_decode_multiple_messages() {
        let handshake_init = initialize_v2_handshake(None).unwrap();
        let mut handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
        let alice_completion =
            initiator_complete_v2_handshake(handshake_response.message.clone(), handshake_init)
                .unwrap();
        let _bob_completion = responder_complete_v2_handshake(
            alice_completion.message.clone(),
            &mut handshake_response,
        )
        .unwrap();
        let mut alice = alice_completion.packet_handler;
        let mut bob = handshake_response.packet_handler;
        let message = b"Hello world".to_vec();
        let mut first_message_to_alice =
            bob.prepare_v2_packet(message.clone(), None, false).unwrap();
        let second_message_to_alice = bob.prepare_v2_packet(message.clone(), None, true).unwrap();
        first_message_to_alice.extend(second_message_to_alice);
        alice
            .receive_v2_packets(first_message_to_alice, None)
            .unwrap();
    }

    #[test]
    fn test_fuzz_decode_multiple_messages() {
        let mut rng = rand::thread_rng();
        let handshake_init = initialize_v2_handshake(None).unwrap();
        let mut handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
        let alice_completion =
            initiator_complete_v2_handshake(handshake_response.message.clone(), handshake_init)
                .unwrap();
        let _bob_completion = responder_complete_v2_handshake(
            alice_completion.message.clone(),
            &mut handshake_response,
        )
        .unwrap();
        let mut alice = alice_completion.packet_handler;
        let mut bob = handshake_response.packet_handler;
        let mut message_to_bob = Vec::new();
        for _ in 0..REKEY_INTERVAL + 100 {
            let message = gen_garbage(420, &mut rng);
            let enc_packet = alice
                .prepare_v2_packet(message.clone(), None, false)
                .unwrap();
            message_to_bob.extend(enc_packet);
        }
        bob.receive_v2_packets(message_to_bob, None).unwrap();
    }

    #[test]
    fn test_partial_decodings() {
        let mut rng = rand::thread_rng();
        let handshake_init = initialize_v2_handshake(None).unwrap();
        let mut handshake_response = receive_v2_handshake(handshake_init.message.clone()).unwrap();
        let alice_completion =
            initiator_complete_v2_handshake(handshake_response.message.clone(), handshake_init)
                .unwrap();
        let _bob_completion = responder_complete_v2_handshake(
            alice_completion.message.clone(),
            &mut handshake_response,
        )
        .unwrap();
        let mut alice = alice_completion.packet_handler;
        let mut bob = handshake_response.packet_handler;
        let mut message_to_bob = Vec::new();
        let message = gen_garbage(420, &mut rng);
        let enc_packet = alice
            .prepare_v2_packet(message.clone(), None, false)
            .unwrap();
        message_to_bob.extend(enc_packet);
        let alice_message_len = bob
            .decypt_len(message_to_bob[..3].try_into().unwrap())
            .unwrap();
        let contents = bob
            .decrypt_contents(message_to_bob[3..3 + alice_message_len].to_vec(), None)
            .unwrap();
        assert_eq!(contents.message.unwrap(), message);
    }

    // The rest are sourced from: https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let mut bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        let first = gen_garbage(100, &mut rng);
        let enc = alice_packet_handler
            .prepare_v2_packet(first.clone(), None, false)
            .unwrap();
        let dec_packet = bob_packet_handler.receive_v2_packets(enc, None).unwrap();
        let secret_message = dec_packet.first().unwrap().message.clone();
        assert_eq!(first, secret_message.unwrap());
        let message: Vec<u8> = vec![0x8e];
        let enc = alice_packet_handler
            .prepare_v2_packet(message.clone(), None, false)
            .unwrap();
        assert_eq!(
            enc,
            hex::decode("7530d2a18720162ac09c25329a60d75adf36eda3c3").unwrap()
        );
    }

    #[test]
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
        );
        let id = session_keys.session_id;
        assert_eq!(
            id.to_vec(),
            hex::decode("9267c54560607de73f18c563b76a2442718879c52dd39852885d4a3c9912c9ea")
                .unwrap()
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Responder);
        let _bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Initiator);
        let message: Vec<u8> = hex::decode("3eb1d4e98035cfd8eeb29bac969ed3824a").unwrap();
        let mut found = 0;
        for i in 0..1000 {
            let enc = alice_packet_handler
                .prepare_v2_packet(message.clone(), None, false)
                .unwrap();
            if hex::encode(&enc)
                .eq("1da1bcf589f9b61872f45b7fa5371dd3f8bdf5d515b0c5f9fe9f0044afb8dc0aa1cd39a8c4")
            {
                found = i;
            }
        }
        assert!(found > 0);
    }

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let _bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        let contents = hex::decode("054290a6c6ba8d80478172e89d32bf690913ae9835de6dcf206ff1f4d652286fe0ddf74deba41d55de3edc77c42a32af79bbea2c00bae7492264c60866ae5a").unwrap();
        let aad = hex::decode("84932a55aac22b51e7b128d31d9f0550da28e6a3f394224707d878603386b2f9d0c6bcd8046679bfed7b68c517e7431e75d9dd34605727d2ef1c2babbf680ecc8d68d2c4886e9953a4034abde6da4189cd47c6bb3192242cf714d502ca6103ee84e08bc2ca4fd370d5ad4e7d06c7fbf496c6c7cc7eb19c40c61fb33df2a9ba48497a96c98d7b10c1f91098a6b7b16b4bab9687f27585ade1491ae0dba6a79e1e2d85dd9d9d45c5135ca5fca3f0f99a60ea39edbc9efc7923111c937913f225d67788d5f7e8852b697e26b92ec7bfcaa334a1665511c2b4c0a42d06f7ab98a9719516c8fd17f73804555ee84ab3b7d1762f6096b778d3cb9c799cbd49a9e4a325197b4e6cc4a5c4651f8b41ff88a92ec428354531f970263b467c77ed11312e2617d0d53fe9a8707f51f9f57a77bfb49afe3d89d85ec05ee17b9186f360c94ab8bb2926b65ca99dae1d6ee1af96cad09de70b6767e949023e4b380e66669914a741ed0fa420a48dbc7bfae5ef2019af36d1022283dd90655f25eec7151d471265d22a6d3f91dc700ba749bb67c0fe4bc0888593fbaf59d3c6fff1bf756a125910a63b9682b597c20f560ecb99c11a92c8c8c3f7fbfaa103146083a0ccaecf7a5f5e735a784a8820155914a289d57d8141870ffcaf588882332e0bcd8779efa931aa108dab6c3cce76691e345df4a91a03b71074d66333fd3591bff071ea099360f787bbe43b7b3dff2a59c41c7642eb79870222ad1c6f2e5a191ed5acea51134679587c9cf71c7d8ee290be6bf465c4ee47897a125708704ad610d8d00252d01959209d7cd04d5ecbbb1419a7e84037a55fefa13dee464b48a35c96bcb9a53e7ed461c3a1607ee00c3c302fd47cd73fda7493e947c9834a92d63dcfbd65aa7c38c3e3a2748bb5d9a58e7495d243d6b741078c8f7ee9c8813e473a323375702702b0afae1550c8341eedf5247627343a95240cb02e3e17d5dca16f8d8d3b2228e19c06399f8ec5c5e9dbe4caef6a0ea3ffb1d3c7eac03ae030e791fa12e537c80d56b55b764cadf27a8701052df1282ba8b5e3eb62b5dc7973ac40160e00722fa958d95102fc25c549d8c0e84bed95b7acb61ba65700c4de4feebf78d13b9682c52e937d23026fb4c6193e6644e2d3c99f91f4f39a8b9fc6d013f89c3793ef703987954dc0412b550652c01d922f525704d32d70d6d4079bc3551b563fb29577b3aecdc9505011701dddfd94830431e7a4918927ee44fb3831ce8c4513839e2deea1287f3fa1ab9b61a256c09637dbc7b4f0f8fbb783840f9c24526da883b0df0c473cf231656bd7bc1aaba7f321fec0971c8c2c3444bff2f55e1df7fea66ec3e440a612db9aa87bb505163a59e06b96d46f50d8120b92814ac5ab146bc78dbbf91065af26107815678ce6e33812e6bf3285d4ef3b7b04b076f21e7820dcbfdb4ad5218cf4ff6a65812d8fcb98ecc1e95e2fa58e3efe4ce26cd0bd400d6036ab2ad4f6c713082b5e3f1e04eb9e3b6c8f63f57953894b9e220e0130308e1fd91f72d398c1e7962ca2c31be83f31d6157633581a0a6910496de8d55d3d07090b6aa087159e388b7e7dec60f5d8a60d93ca2ae91296bd484d916bfaaa17c8f45ea4b1a91b37c82821199a2b7596672c37156d8701e7352aa48671d3b1bbbd2bd5f0a2268894a25b0cb2514af39c8743f8cce8ab4b523053739fd8a522222a09acf51ac704489cf17e4b7125455cb8f125b4d31af1eba1f8cf7f81a5a100a141a7ee72e8083e065616649c241f233645c5fc865d17f0285f5c52d9f45312c979bfb3ce5f2a1b951deddf280ffb3f370410cffd1583bfa90077835aa201a0712d1dcd1293ee177738b14e6b5e2a496d05220c3253bb6578d6aff774be91946a614dd7e879fb3dcf7451e0b9adb6a8c44f53c2c464bcc0019e9fad89cac7791a0a3f2974f759a9856351d4d2d7c5612c17cfc50f8479945df57716767b120a590f4bf656f4645029a525694d8a238446c5f5c2c1c995c09c1405b8b1eb9e0352ffdf766cc964f8dcf9f8f043dfab6d102cf4b298021abd78f1d9025fa1f8e1d710b38d9d1652f2d88d1305874ec41609b6617b65c5adb19b6295dc5c5da5fdf69f28144ea12f17c3c6fcce6b9b5157b3dfc969d6725fa5b098a4d9b1d31547ed4c9187452d281d0a5d456008caf1aa251fac8f950ca561982dc2dc908d3691ee3b6ad3ae3d22d002577264ca8e49c523bd51c4846be0d198ad9407bf6f7b82c79893eb2c05fe9981f687a97a4f01fe45ff8c8b7ecc551135cd960a0d6001ad35020be07ffb53cb9e731522ca8ae9364628914b9b8e8cc2f37f03393263603cc2b45295767eb0aac29b0930390eb89587ab2779d2e3decb8042acece725ba42eda650863f418f8d0d50d104e44fbbe5aa7389a4a144a8cecf00f45fb14c39112f9bfb56c0acbd44fa3ff261f5ce4acaa5134c2c1d0cca447040820c81ab1bcdc16aa075b7c68b10d06bbb7ce08b5b805e0238f24402cf24a4b4e00701935a0c68add3de090903f9b85b153cb179a582f57113bfc21c2093803f0cfa4d9d4672c2b05a24f7e4c34a8e9101b70303a7378b9c50b6cddd46814ef7fd73ef6923feceab8fc5aa8b0d185f2e83c7a99dcb1077c0ab5c1f5d5f01ba2f0420443f75c4417db9ebf1665efbb33dca224989920a64b44dc26f682cc77b4632c8454d49135e52503da855bc0f6ff8edc1145451a9772c06891f41064036b66c3119a0fc6e80dffeb65dc456108b7ca0296f4175fff3ed2b0f842cd46bd7e86f4c62dfaf1ddbf836263c00b34803de164983d0811cebfac86e7720c726d3048934c36c23189b02386a722ca9f0fe00233ab50db928d3bccea355cc681144b8b7edcaae4884d5a8f04425c0890ae2c74326e138066d8c05f4c82b29df99b034ea727afde590a1f2177ace3af99cfb1729d6539ce7f7f7314b046aab74497e63dd399e1f7d5f16517c23bd830d1fdee810f3c3b77573dd69c4b97d80d71fb5a632e00acdfa4f8e829faf3580d6a72c40b28a82172f8dcd4627663ebf6069736f21735fd84a226f427cd06bb055f94e7c92f31c48075a2955d82a5b9d2d0198ce0d4e131a112570a8ee40fb80462a81436a58e7db4e34b6e2c422e82f934ecda9949893da5730fc5c23c7c920f363f85ab28cc6a4206713c3152669b47efa8238fa826735f17b4e78750276162024ec85458cd5808e06f40dd9fd43775a456a3ff6cae90550d76d8b2899e0762ad9a371482b3e38083b1274708301d6346c22fea9bb4b73db490ff3ab05b2f7f9e187adef139a7794454b7300b8cc64d3ad76c0e4bc54e08833a4419251550655380d675bc91855aeb82585220bb97f03e976579c08f321b5f8f70988d3061f41465517d53ac571dbf1b24b94443d2e9a8e8a79b392b3d6a4ecdd7f626925c365ef6221305105ce9b5f5b6ecc5bed3d702bd4b7f5008aa8eb8c7aa3ade8ecf6251516fbefeea4e1082aa0e1848eddb31ffe44b04792d296054402826e4bd054e671f223e5557e4c94f89ca01c25c44f1a2ff2c05a70b43408250705e1b858bf0670679fdcd379203e36be3500dd981b1a6422c3cf15224f7fefdef0a5f225c5a09d15767598ecd9e262460bb33a4b5d09a64591efabc57c923d3be406979032ae0bc0997b65336a06dd75b253332ad6a8b63ef043f780a1b3fb6d0b6cad98b1ef4a02535eb39e14a866cfc5fc3a9c5deb2261300d71280ebe66a0776a151469551c3c5fa308757f956655278ec6330ae9e3625468c5f87e02cd9a6489910d4143c1f4ee13aa21a6859d907b788e28572fecee273d44e4a900fa0aa668dd861a60fb6b6b12c2c5ef3c8df1bd7ef5d4b0d1cdb8c15fffbb365b9784bd94abd001c6966216b9b67554ad7cb7f958b70092514f7800fc40244003e0fd1133a9b850fb17f4fcafde07fc87b07fb510670654a5d2d6fc9876ac74728ea41593beef003d6858786a52d3a40af7529596767c17000bfaf8dc52e871359f4ad8bf6e7b2853e5229bdf39657e213580294a5317c5df172865e1e17fe37093b585e04613f5f078f761b2b1752eb32983afda24b523af8851df9a02b37e77f543f18888a782a994a50563334282bf9cdfccc183fdf4fcd75ad86ee0d94f91ee2300a5befbccd14e03a77fc031a8cfe4f01e4c5290f5ac1da0d58ea054bd4837cfd93e5e34fc0eb16e48044ba76131f228d16cde9b0bb978ca7cdcd10653c358bdb26fdb723a530232c32ae0a4cecc06082f46e1c1d596bfe60621ad1e354e01e07b040cc7347c016653f44d926d13ca74e6cbc9d4ab4c99f4491c95c76fff5076b3936eb9d0a286b97c035ca88a3c6309f5febfd4cdaac869e4f58ed409b1e9eb4192fb2f9c2f12176d460fd98286c9d6df84598f260119fd29c63f800c07d8df83d5cc95f8c2fea2812e7890e8a0718bb1e031ecbebc0436dcf3e3b9a58bcc06b4c17f711f80fe1dffc3326a6eb6e00283055c6dabe20d311bfd5019591b7954f8163c9afad9ef8390a38f3582e0a79cdf0353de8eeb6b5f9f27b16ffdef7dd62869b4840ee226ccdce95e02c4545eb981b60571cd83f03dc5eaf8c97a0829a4318a9b3dc06c0e003db700b2260ff1fa8fee66890e637b109abb03ec901b05ca599775f48af50154c0e67d82bf0f558d7d3e0778dc38bea1eb5f74dc8d7f90abdf5511a424be66bf8b6a3cacb477d2e7ef4db68d2eba4d5289122d851f9501ba7e9c4957d8eba3be3fc8e785c4265a1d65c46f2809b70846c693864b169c9dcb78be26ea14b8613f145b01887222979a9e67aee5f800caa6f5c4229bdeefc901232ace6143c9865e4d9c07f51aa200afaf7e48a7d1d8faf366023beab12906ffcb3eaf72c0eb68075e4daf3c080e0c31911befc16f0cc4a09908bb7c1e26abab38bd7b788e1a09c0edf1a35a38d2ff1d3ed47fcdaae2f0934224694f5b56705b9409b6d3d64f3833b686f7576ec64bbdd6ff174e56c2d1edac0011f904681a73face26573fbba4e34652f7ae84acfb2fa5a5b3046f98178cd0831df7477de70e06a4c00e305f31aafc026ef064dd68fd3e4252b1b91d617b26c6d09b6891a00df68f105b5962e7f9d82da101dd595d286da721443b72b2aba2377f6e7772e33b3a5e3753da9c2578c5d1daab80187f55518c72a64ee150a7cb5649823c08c9f62cd7d020b45ec2cba8310db1a7785a46ab24785b4d54ff1660b5ca78e05a9a55edba9c60bf044737bc468101c4e8bd1480d749be5024adefca1d998abe33eaeb6b11fbb39da5d905fdd3f611b2e51517ccee4b8af72c2d948573505590d61a6783ab7278fc43fe55b1fcc0e7216444d3c8039bb8145ef1ce01c50e95a3f3feab0aee883fdb94cc13ee4d21c542aa795e18932228981690f4d4c57ca4db6eb5c092e29d8a05139d509a8aeb48baa1eb97a76e597a32b280b5e9d6c36859064c98ff96ef5126130264fa8d2f49213870d9fb036cff95da51f270311d9976208554e48ffd486470d0ecdb4e619ccbd8226147204baf8e235f54d8b1cba8fa34a9a4d055de515cdf180d2bb6739a175183c472e30b5c914d09eeb1b7dafd6872b38b48c6afc146101200e6e6a44fe5684e220adc11f5c403ddb15df8051e6bdef09117a3a5349938513776286473a3cf1d2788bb875052a2e6459fa7926da33380149c7f98d7700528a60c954e6f5ecb65842fde69d614be69eaa2040a4819ae6e756accf936e14c1e894489744a79c1f2c1eb295d13e2d767c09964b61f9cfe497649f712").unwrap();
        let auth = alice_packet_handler
            .prepare_v2_packet(contents, Some(aad), false)
            .unwrap();
        let challenge = hex::decode("8da7de6ea7bf2a81a396a42880ba1f5756734c4821309ac9aeffa2a26ce86873b9dc4935a772de6ec5162c6d075b14536800fb174841153511bfb597e992e2fe8a450c4bce102cc550bb37fd564c4d60bf884e").unwrap();
        assert_eq!(auth, challenge);
    }

    #[test]
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
        );
        let id = session_keys.session_id;
        assert_eq!(
            id.to_vec(),
            hex::decode("7ec02fea8c1484e3d0875f978c5f36d63545e2e4acf56311394422f4b66af612")
                .unwrap()
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Responder);
        let _bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Initiator);
        let message: Vec<u8> = hex::decode("7e0e78eb6990b059e6cf0ded66ea93ef82e72aa2f18ac24f2fc6ebab561ae557420729da103f64cecfa20527e15f9fb669a49bbbf274ef0389b3e43c8c44e5f60bf2ac38e2b55e7ec4273dba15ba41d21f8f5b3ee1688b3c29951218caf847a97fb50d75a86515d445699497d968164bf740012679b8962de573be941c62b7ef").unwrap();
        let mut found = 0;
        for i in 0..224 {
            let enc = alice_packet_handler
                .prepare_v2_packet(message.clone(), None, true)
                .unwrap();
            if hex::encode(enc).contains("729847a3e9eba7a5bff454b5de3b393431ee360736b6c030d7a5bd01d1203d2e98f528543fd2bf886ccaa1ada5e215a730a36b3f4abfc4e252c89eb01d9512f94916dae8a76bf16e4da28986ffe159090fe5267ee3394300b7ccf4dfad389a26321b3a3423e4594a82ccfbad16d6561ecb8772b0cb040280ff999a29e3d9d4fd") {
                found = i;
            }
        }
        assert!(found > 0);
    }

    #[test]
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
        );
        let mut alice_packet_handler =
            PacketHandler::new(session_keys.clone(), HandshakeRole::Initiator);
        let _bob_packet_handler = PacketHandler::new(session_keys, HandshakeRole::Responder);
        let contents = hex::decode("00cf68f8f7ac49ffaa02c4864fdf6dfe7bbf2c740b88d98c50ebafe32c92f3427f57601ffcb21a3435979287db8fee6c302926741f9d5e464c647eeb9b7acaeda46e00abd7506fc9a719847e9a7328215801e96198dac141a15c7c2f68e0690dd1176292a0dded04d1f548aad88f1aebdc0a8f87da4bb22df32dd7c160c225b843e83f6525d6d484f502f16d923124fc538794e21da2eb689d18d87406ecced5b9f92137239ed1d37bcfa7836641a83cf5e0a1cf63f51b06f158e499a459ede41c").unwrap();
        let mut found = 0;
        for i in 0..449 {
            let enc = alice_packet_handler
                .prepare_v2_packet(contents.clone(), None, false)
                .unwrap();
            if hex::encode(enc).contains("77b4656934a82de1a593d8481f020194ddafd8cac441f9d72aeb8721e6a14f49698ca6d9b2b6d59d07a01aa552fd4d5b68d0d1617574c77dea10bfadbaa31b83885b7ceac2fd45e3e4a331c51a74e7b1698d81b64c87c73c5b9258b4d83297f9debc2e9aa07f8572ff434dc792b83ecf07b3197de8dc9cf7be56acb59c66cff5") {
                found = i;
            }
        }
        assert!(found > 0);
    }
}
