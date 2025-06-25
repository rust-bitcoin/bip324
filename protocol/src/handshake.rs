// SPDX-License-Identifier: CC0-1.0

//! # BIP-324 V2 Transport Protocol Handshake
//!
//! 1. **Key Exchange**: Both peers generate and exchange public keys using ElligatorSwift encoding.
//! 2. **Garbage**: Optional garbage bytes are sent to obscure traffic patterns.
//! 3. **Decoy Packets**: Optional decoy packets can be sent to further obscure traffic patterns.
//! 4. **Version Authentication**: Version packets are exchanged to negotiate the protocol version for the channel.
//! 5. **Session Establishment**: The secure communication channel is ready for message exchange.
//! ```

use bitcoin::{
    key::Secp256k1,
    secp256k1::{
        ellswift::{ElligatorSwift, ElligatorSwiftParty},
        PublicKey, SecretKey, Signing,
    },
    Network,
};
use rand::Rng;

use crate::{
    CipherSession, Error, InboundCipher, OutboundCipher, PacketType, Role, SessionKeyMaterial,
    NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINTOR_BYTES, NUM_LENGTH_BYTES, VERSION_CONTENT,
};

/// Initial buffer for decoy and version packets in the handshake.
/// The buffer may have to be expanded if a party is sending large
/// decoy packets.
pub const NUM_INITIAL_HANDSHAKE_BUFFER_BYTES: usize = 4096;
// Maximum number of garbage bytes before the terminator.
const MAX_NUM_GARBAGE_BYTES: usize = 4095;

/// A point on the curve used to complete the handshake.
#[derive(Clone)]
pub struct EcdhPoint {
    secret_key: SecretKey,
    elligator_swift: ElligatorSwift,
}

/// **Initial state** of the handshake state machine which holds local secret materials.
pub struct Initialized {
    point: EcdhPoint,
}

/// **Second state** after sending the local public key.
pub struct SentKey {
    point: EcdhPoint,
    bytes_written: usize,
}

/// **Third state** after receiving the remote's public key and
/// generating the shared secret materials for the session.
pub struct ReceivedKey {
    session_keys: SessionKeyMaterial,
}

/// **Fourth state** after sending the version packet.
pub struct SentVersion {
    cipher: CipherSession,
    remote_garbage_terminator: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
    bytes_written: usize,
}

/// Success variants for receive_version.
pub enum HandshakeAuthentication<'a> {
    /// Successfully completed.
    Complete {
        cipher: CipherSession,
        bytes_consumed: usize,
    },
    /// Need more data - returns handshake for caller to retry with more ciphertext.
    NeedMoreData(Handshake<'a, SentVersion>),
}

/// Handshake state-machine to establish the secret material in the communication channel.
///
/// The handshake progresses through multiple states, enforcing the protocol sequence at compile time.
///
/// 1. `Initialized` - Initial state with local secret materials.
/// 2. `SentKey` - After sending local public key and optional garbage.  
/// 3. `ReceivedKey` - After receiving remote's public key.
/// 4. `SentVersion` - After sending local garbage terminator and version packet.
/// 5. Complete - After receiving and authenticating remote's garbage, garbage terminator, decoy packets, and version packet.
pub struct Handshake<'a, State> {
    /// Bitcoin network both peers are operating on.
    network: Network,
    /// Local role in the handshake, initiator or responder.
    role: Role,
    /// Optional local garbage bytes to send along in handshake.
    garbage: Option<&'a [u8]>,
    /// State-specific data.
    state: State,
}

// Methods available in all states
impl<'a, State> Handshake<'a, State> {
    /// Get the network this handshake is operating on.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the local role in the handshake.
    pub fn role(&self) -> Role {
        self.role
    }
}

// Initialized state implementation
impl<'a> Handshake<'a, Initialized> {
    /// Initialize a V2 transport handshake with a remote peer.
    #[cfg(feature = "std")]
    pub fn new(network: Network, role: Role) -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let curve = Secp256k1::signing_only();
        Self::new_with_rng(network, role, &mut rng, &curve)
    }

    /// Initialize a V2 transport handshake with remote peer using supplied RNG and secp context.
    pub fn new_with_rng<C: Signing>(
        network: Network,
        role: Role,
        rng: &mut impl Rng,
        curve: &Secp256k1<C>,
    ) -> Result<Self, Error> {
        let mut secret_key_buffer = [0u8; 32];
        rng.fill(&mut secret_key_buffer[..]);
        let sk = SecretKey::from_slice(&secret_key_buffer)?;
        let pk = PublicKey::from_secret_key(curve, &sk);
        let es = ElligatorSwift::from_pubkey(pk);

        let point = EcdhPoint {
            secret_key: sk,
            elligator_swift: es,
        };

        Ok(Handshake {
            network,
            role,
            garbage: None,
            state: Initialized { point },
        })
    }

    /// Calculate how many bytes send_key() will write to buffer.
    pub fn send_key_len(garbage: Option<&[u8]>) -> usize {
        NUM_ELLIGATOR_SWIFT_BYTES + garbage.map(|g| g.len()).unwrap_or(0)
    }

    /// Send local public key and optional garbage.
    pub fn send_key(
        mut self,
        garbage: Option<&'a [u8]>,
        output_buffer: &mut [u8],
    ) -> Result<Handshake<'a, SentKey>, Error> {
        // Validate garbage length
        if let Some(g) = garbage {
            if g.len() > MAX_NUM_GARBAGE_BYTES {
                return Err(Error::TooMuchGarbage);
            }
        }

        let required_len = Self::send_key_len(garbage);
        if output_buffer.len() < required_len {
            return Err(Error::BufferTooSmall {
                required_bytes: required_len,
            });
        }

        // Write local ellswift public key.
        output_buffer[..NUM_ELLIGATOR_SWIFT_BYTES]
            .copy_from_slice(&self.state.point.elligator_swift.to_array());
        let mut written = NUM_ELLIGATOR_SWIFT_BYTES;

        // Write garbage if provided.
        if let Some(g) = garbage {
            output_buffer[written..written + g.len()].copy_from_slice(g);
            written += g.len();
        }

        // Store garbage for later use.
        self.garbage = garbage;

        Ok(Handshake {
            network: self.network,
            role: self.role,
            garbage: self.garbage,
            state: SentKey {
                point: self.state.point,
                bytes_written: written,
            },
        })
    }
}

// SentKey state implementation
impl<'a> Handshake<'a, SentKey> {
    /// Get how many bytes were written by send_key().
    pub fn bytes_written(&self) -> usize {
        self.state.bytes_written
    }

    /// Process received key material.
    pub fn receive_key(
        self,
        their_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    ) -> Result<Handshake<'a, ReceivedKey>, Error> {
        let their_ellswift = ElligatorSwift::from_array(their_key);

        // Check for V1 protocol magic bytes
        if self.network.magic()
            == bitcoin::p2p::Magic::from_bytes(
                their_key[..4]
                    .try_into()
                    .expect("64 byte array to have 4 byte prefix"),
            )
        {
            return Err(Error::V1Protocol);
        }

        // Compute session keys using ECDH
        let (initiator_ellswift, responder_ellswift, secret, party) = match self.role {
            Role::Initiator => (
                self.state.point.elligator_swift,
                their_ellswift,
                self.state.point.secret_key,
                ElligatorSwiftParty::A,
            ),
            Role::Responder => (
                their_ellswift,
                self.state.point.elligator_swift,
                self.state.point.secret_key,
                ElligatorSwiftParty::B,
            ),
        };

        let session_keys = SessionKeyMaterial::from_ecdh(
            initiator_ellswift,
            responder_ellswift,
            secret,
            party,
            self.network,
        )?;

        Ok(Handshake {
            network: self.network,
            role: self.role,
            garbage: self.garbage,
            state: ReceivedKey { session_keys },
        })
    }
}

// ReceivedKey state implementation
impl<'a> Handshake<'a, ReceivedKey> {
    /// Calculate how many bytes send_version() will write to buffer.
    pub fn send_version_len(decoys: Option<&[&[u8]]>) -> usize {
        let mut len = NUM_GARBAGE_TERMINTOR_BYTES
            + OutboundCipher::encryption_buffer_len(VERSION_CONTENT.len());

        // Add decoy packets length.
        if let Some(decoys) = decoys {
            for decoy in decoys {
                len += OutboundCipher::encryption_buffer_len(decoy.len());
            }
        }

        len
    }

    /// Send garbage terminator, optional decoys, and version packet.
    pub fn send_version(
        self,
        output_buffer: &mut [u8],
        decoys: Option<&[&[u8]]>,
    ) -> Result<Handshake<'a, SentVersion>, Error> {
        let required_len = Self::send_version_len(decoys);
        if output_buffer.len() < required_len {
            return Err(Error::BufferTooSmall {
                required_bytes: required_len,
            });
        }

        let mut cipher = CipherSession::new(self.state.session_keys.clone(), self.role);

        // Write garbage terminator and determine remote terminator.
        let remote_garbage_terminator = match self.role {
            Role::Initiator => {
                output_buffer[..NUM_GARBAGE_TERMINTOR_BYTES]
                    .copy_from_slice(&self.state.session_keys.initiator_garbage_terminator);
                self.state.session_keys.responder_garbage_terminator
            }
            Role::Responder => {
                output_buffer[..NUM_GARBAGE_TERMINTOR_BYTES]
                    .copy_from_slice(&self.state.session_keys.responder_garbage_terminator);
                self.state.session_keys.initiator_garbage_terminator
            }
        };

        let mut bytes_written = NUM_GARBAGE_TERMINTOR_BYTES;
        // Local garbage is authenticated in first packet no
        // matter if it is a decoy or genuine.
        let mut aad = self.garbage;

        if let Some(decoys) = decoys {
            for decoy in decoys {
                let packet_len = OutboundCipher::encryption_buffer_len(decoy.len());
                cipher.outbound().encrypt(
                    decoy,
                    &mut output_buffer[bytes_written..bytes_written + packet_len],
                    PacketType::Decoy,
                    aad,
                )?;
                aad = None;
                bytes_written += packet_len;
            }
        }

        // Write version packet
        let version_packet_len = OutboundCipher::encryption_buffer_len(VERSION_CONTENT.len());
        cipher.outbound().encrypt(
            &VERSION_CONTENT,
            &mut output_buffer[bytes_written..bytes_written + version_packet_len],
            PacketType::Genuine,
            aad,
        )?;
        bytes_written += version_packet_len;

        Ok(Handshake {
            network: self.network,
            role: self.role,
            garbage: self.garbage,
            state: SentVersion {
                cipher,
                remote_garbage_terminator,
                bytes_written,
            },
        })
    }
}

// SentVersion state implementation
impl<'a> Handshake<'a, SentVersion> {
    /// Get how many bytes were written by send_version().
    pub fn bytes_written(&self) -> usize {
        self.state.bytes_written
    }

    /// Authenticate garbage and version packet.
    pub fn receive_version(
        mut self,
        input_buffer: &[u8],
        output_buffer: &mut [u8],
    ) -> Result<HandshakeAuthentication<'a>, Error> {
        let (garbage, ciphertext) = match self.split_garbage(input_buffer) {
            Ok(split) => split,
            Err(Error::CiphertextTooSmall) => {
                return Ok(HandshakeAuthentication::NeedMoreData(self))
            }
            Err(e) => return Err(e),
        };

        let mut aad = if garbage.is_empty() {
            None
        } else {
            Some(garbage)
        };
        let mut ciphertext_index = 0;
        let mut found_version = false;

        // First packet authenticates remote garbage.
        // Continue through decoys until we find version packet.
        while !found_version {
            match self.decrypt_packet(&ciphertext[ciphertext_index..], output_buffer, aad) {
                Ok((packet_type, bytes_consumed)) => {
                    aad = None;
                    ciphertext_index += bytes_consumed;
                    found_version = matches!(packet_type, PacketType::Genuine);
                }
                Err(Error::CiphertextTooSmall) => {
                    return Ok(HandshakeAuthentication::NeedMoreData(self))
                }
                Err(e) => return Err(e),
            }
        }

        // Calculate total bytes consumed (garbage + terminator + packets)
        let bytes_consumed = garbage.len() + NUM_GARBAGE_TERMINTOR_BYTES + ciphertext_index;

        Ok(HandshakeAuthentication::Complete {
            cipher: self.state.cipher,
            bytes_consumed,
        })
    }

    /// Split buffer on garbage terminator.
    fn split_garbage<'b>(&self, buffer: &'b [u8]) -> Result<(&'b [u8], &'b [u8]), Error> {
        let terminator = &self.state.remote_garbage_terminator;

        if let Some(index) = buffer
            .windows(terminator.len())
            .position(|window| window == terminator)
        {
            Ok((&buffer[..index], &buffer[index + terminator.len()..]))
        } else if buffer.len() >= MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES {
            Err(Error::NoGarbageTerminator)
        } else {
            Err(Error::CiphertextTooSmall)
        }
    }

    fn decrypt_packet(
        &mut self,
        ciphertext: &[u8],
        output_buffer: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<(PacketType, usize), Error> {
        if ciphertext.len() < NUM_LENGTH_BYTES {
            return Err(Error::CiphertextTooSmall);
        }

        let packet_len = self.state.cipher.inbound().decrypt_packet_len(
            ciphertext[..NUM_LENGTH_BYTES]
                .try_into()
                .expect("Checked length above"),
        );

        if ciphertext.len() < NUM_LENGTH_BYTES + packet_len {
            return Err(Error::CiphertextTooSmall);
        }

        // Check output buffer is large enough.
        let plaintext_len = InboundCipher::decryption_buffer_len(packet_len);
        if output_buffer.len() < plaintext_len {
            return Err(Error::BufferTooSmall {
                required_bytes: plaintext_len,
            });
        }

        let packet_type = self.state.cipher.inbound().decrypt(
            &ciphertext[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len],
            &mut output_buffer[..plaintext_len],
            aad,
        )?;

        Ok((packet_type, NUM_LENGTH_BYTES + packet_len))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn test_handshake() {
        let initiator_garbage = vec![1u8, 2u8, 3u8];
        let responder_garbage = vec![4u8, 5u8];

        let init_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();

        // Send initiator key + garbage.
        let mut init_buffer =
            vec![0u8; Handshake::<Initialized>::send_key_len(Some(&initiator_garbage))];
        let init_handshake = init_handshake
            .send_key(Some(&initiator_garbage), &mut init_buffer)
            .unwrap();
        assert_eq!(init_handshake.bytes_written(), 64 + initiator_garbage.len());

        let resp_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();

        // Send responder key + garbage.
        let mut resp_buffer =
            vec![0u8; Handshake::<Initialized>::send_key_len(Some(&responder_garbage))];
        let resp_handshake = resp_handshake
            .send_key(Some(&responder_garbage), &mut resp_buffer)
            .unwrap();
        assert_eq!(resp_handshake.bytes_written(), 64 + responder_garbage.len());

        // Initiator receives responder's key.
        let init_handshake = init_handshake
            .receive_key(resp_buffer[..64].try_into().unwrap())
            .unwrap();

        // Responder receives initiator's key.
        let resp_handshake = resp_handshake
            .receive_key(init_buffer[..64].try_into().unwrap())
            .unwrap();

        // Create decoy packets for both sides.
        let init_decoy1 = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let init_decoy2 = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01];
        let init_decoys = vec![init_decoy1.as_slice(), init_decoy2.as_slice()];

        let resp_decoy1 = vec![0xAB, 0xCD, 0xEF];
        let resp_decoys = vec![resp_decoy1.as_slice()];

        // Initiator sends decoys and version.
        let mut init_version_buffer =
            vec![0u8; Handshake::<ReceivedKey>::send_version_len(Some(&init_decoys))];
        let init_handshake = init_handshake
            .send_version(&mut init_version_buffer, Some(&init_decoys))
            .unwrap();

        // Responder sends decoys and version.
        let mut resp_version_buffer =
            vec![0u8; Handshake::<ReceivedKey>::send_version_len(Some(&resp_decoys))];
        let resp_handshake = resp_handshake
            .send_version(&mut resp_version_buffer, Some(&resp_decoys))
            .unwrap();

        let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES];

        // Initiator receives responder's garbage, decoys, and version.
        let full_resp_message = [&responder_garbage[..], &resp_version_buffer[..]].concat();
        match init_handshake
            .receive_version(&full_resp_message, &mut packet_buffer)
            .unwrap()
        {
            HandshakeAuthentication::Complete { bytes_consumed, .. } => {
                assert_eq!(bytes_consumed, full_resp_message.len());
            }
            HandshakeAuthentication::NeedMoreData(_) => panic!("Should have completed"),
        }

        // Responder receives initiator's garbage, decoys, and version.
        let full_init_message = [&initiator_garbage[..], &init_version_buffer[..]].concat();
        match resp_handshake
            .receive_version(&full_init_message, &mut packet_buffer)
            .unwrap()
        {
            HandshakeAuthentication::Complete { bytes_consumed, .. } => {
                assert_eq!(bytes_consumed, full_init_message.len());
            }
            HandshakeAuthentication::NeedMoreData(_) => panic!("Should have completed"),
        }
    }

    #[test]
    fn test_handshake_garbage_length_check() {
        // Test with valid garbage length
        let valid_garbage = vec![0u8; MAX_NUM_GARBAGE_BYTES];
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let mut buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES + MAX_NUM_GARBAGE_BYTES];
        let result = handshake.send_key(Some(&valid_garbage), &mut buffer);
        assert!(result.is_ok());

        // Test with garbage length exceeding MAX_NUM_GARBAGE_BYTES
        let too_much_garbage = vec![0u8; MAX_NUM_GARBAGE_BYTES + 1];
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let result = handshake.send_key(Some(&too_much_garbage), &mut buffer);
        assert!(matches!(result, Err(Error::TooMuchGarbage)));

        // Test too small of buffer
        let buffer_size = NUM_ELLIGATOR_SWIFT_BYTES + valid_garbage.len() - 1;
        let mut too_small_buffer = vec![0u8; buffer_size];
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let result = handshake.send_key(Some(&valid_garbage), &mut too_small_buffer);
        assert!(
            matches!(result, Err(Error::BufferTooSmall { required_bytes }) if required_bytes == NUM_ELLIGATOR_SWIFT_BYTES + valid_garbage.len()),
            "Expected BufferTooSmall with correct size"
        );

        // Test with no garbage
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let result = handshake.send_key(None, &mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handshake_receive_version_buffer() {
        // Test the scenario where receive_version needs more data.
        let init_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let resp_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();

        let mut init_buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let init_handshake = init_handshake.send_key(None, &mut init_buffer).unwrap();

        let mut resp_buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let resp_handshake = resp_handshake.send_key(None, &mut resp_buffer).unwrap();

        let init_handshake = init_handshake
            .receive_key(resp_buffer[..64].try_into().unwrap())
            .unwrap();
        let resp_handshake = resp_handshake
            .receive_key(init_buffer[..64].try_into().unwrap())
            .unwrap();

        let mut init_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
        let _init_handshake = init_handshake
            .send_version(&mut init_version_buffer, None)
            .unwrap();

        let mut resp_version_buffer = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
        let resp_handshake = resp_handshake
            .send_version(&mut resp_version_buffer, None)
            .unwrap();

        let mut packet_buffer = vec![0u8; NUM_INITIAL_HANDSHAKE_BUFFER_BYTES];

        // Feed data in very small chunks to trigger NeedMoreData.
        let partial_data_1 = &init_version_buffer[..1];
        let returned_handshake = match resp_handshake
            .receive_version(partial_data_1, &mut packet_buffer)
            .unwrap()
        {
            HandshakeAuthentication::NeedMoreData(handshake) => handshake,
            HandshakeAuthentication::Complete { .. } => {
                panic!("Should have needed more data with 1 byte")
            }
        };

        // Feed a bit more data - still probably not enough.
        let partial_data_2 = &init_version_buffer[..5];
        let returned_handshake = match returned_handshake
            .receive_version(partial_data_2, &mut packet_buffer)
            .unwrap()
        {
            HandshakeAuthentication::NeedMoreData(handshake) => handshake,
            HandshakeAuthentication::Complete { .. } => {
                panic!("Should have needed more data with 5 bytes")
            }
        };

        // Now provide the complete data.
        match returned_handshake
            .receive_version(&init_version_buffer, &mut packet_buffer)
            .unwrap()
        {
            HandshakeAuthentication::Complete { bytes_consumed, .. } => {
                assert_eq!(bytes_consumed, init_version_buffer.len());
            }
            HandshakeAuthentication::NeedMoreData(_) => {
                panic!("Should have completed with full data")
            }
        }
    }

    #[test]
    fn test_handshake_no_garbage_terminator() {
        // Create a handshake and bring it to the SentVersion state to test split_garbage
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let mut buffer = vec![0u8; 64];
        let handshake = handshake.send_key(None, &mut buffer).unwrap();

        // Create a fake peer key to receive
        let fake_peer_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let handshake = handshake.receive_key(fake_peer_key).unwrap();

        // Send version to get to SentVersion state
        let mut version_buffer = vec![0u8; 1024];
        let handshake = handshake.send_version(&mut version_buffer, None).unwrap();

        // Test with a buffer that is too long (should fail to find terminator)
        let test_buffer = vec![0; MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES];
        let result = handshake.split_garbage(&test_buffer);
        assert!(matches!(result, Err(Error::NoGarbageTerminator)));

        // Test with a buffer that's just short of the required length
        let short_buffer = vec![0; MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES - 1];
        let result = handshake.split_garbage(&short_buffer);
        assert!(matches!(result, Err(Error::CiphertextTooSmall)));
    }
}
