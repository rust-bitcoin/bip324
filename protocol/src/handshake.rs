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
    CipherSession, Error, OutboundCipher, PacketType, Role, SessionKeyMaterial,
    NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINTOR_BYTES, VERSION_CONTENT,
};

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
pub struct SentKey<'a> {
    point: EcdhPoint,
    local_garbage: Option<&'a [u8]>,
}

/// **Third state** after receiving the remote's public key and
/// generating the shared secret materials for the session.
pub struct ReceivedKey<'a> {
    session_keys: SessionKeyMaterial,
    local_garbage: Option<&'a [u8]>,
}

/// **Fourth state** after sending the decoy and version packets.
pub struct SentVersion {
    cipher: CipherSession,
    remote_garbage_terminator: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
}

/// **Fifth state** after receiving the remote's garbage and garbage terminator.
pub struct ReceivedGarbage<'a> {
    cipher: CipherSession,
    remote_garbage: Option<&'a [u8]>,
}

/// Success variants for reading remote garbage.
pub enum GarbageResult<'a> {
    /// Successfully found garbage.
    FoundGarbage {
        handshake: Handshake<ReceivedGarbage<'a>>,
        consumed_bytes: usize,
    },
    /// No garbage terminator found, the input buffer needs to be extended.
    NeedMoreData(Handshake<SentVersion>),
}

/// Success variants for receiving remote version.
pub enum VersionResult<'a> {
    /// Successfully completed handshake.
    Complete { cipher: CipherSession },
    /// Packet was a decoy, read the next to see if version.
    Decoy(Handshake<ReceivedGarbage<'a>>),
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
pub struct Handshake<State> {
    /// Bitcoin network both peers are operating on.
    network: Network,
    /// Local role in the handshake, initiator or responder.
    role: Role,
    /// State-specific data.
    state: State,
}

// Methods available in all states.
impl<State> Handshake<State> {
    /// Get the network this handshake is operating on.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the local role in the handshake.
    pub fn role(&self) -> Role {
        self.role
    }
}

impl Handshake<Initialized> {
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
            state: Initialized { point },
        })
    }

    /// Calculate how many bytes send_key() will write to buffer.
    pub fn send_key_len(garbage: Option<&[u8]>) -> usize {
        NUM_ELLIGATOR_SWIFT_BYTES + garbage.map(|g| g.len()).unwrap_or(0)
    }

    /// Send local public key and optional garbage to initiate the handshake.
    ///
    /// # Parameters
    ///
    /// * `garbage` - Optional garbage bytes to append after the public key. Limited to 4095 bytes.
    /// * `output_buffer` - Buffer to write the key and garbage. Must have sufficient capacity
    ///   as calculated by `send_key_len()`.
    ///
    /// # Returns
    ///
    /// `Ok(Handshake<SentKey>)` - Ready to receive remote peer's key material.
    ///
    /// # Errors
    ///
    /// * `TooMuchGarbage` - Garbage exceeds 4095 byte limit.
    /// * `BufferTooSmall` - Output buffer insufficient for key + garbage.
    pub fn send_key<'a>(
        self,
        garbage: Option<&'a [u8]>,
        output_buffer: &mut [u8],
    ) -> Result<Handshake<SentKey<'a>>, Error> {
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

        // Write garbage if provided.
        if let Some(g) = garbage {
            output_buffer[NUM_ELLIGATOR_SWIFT_BYTES..NUM_ELLIGATOR_SWIFT_BYTES + g.len()]
                .copy_from_slice(g);
        }

        Ok(Handshake {
            network: self.network,
            role: self.role,
            state: SentKey {
                point: self.state.point,
                local_garbage: garbage,
            },
        })
    }
}

impl<'a> Handshake<SentKey<'a>> {
    /// Process the remote peer's public key and derive shared session secrets.
    ///
    /// This is the **second state transition** in the handshake process, moving from
    /// `SentKey` to `ReceivedKey` state. The method performs ECDH key exchange using
    /// the received remote public key and generates all cryptographic material needed
    /// for the secure session.
    ///
    /// # Parameters
    ///
    /// * `their_key` - The remote peer's 64-byte ElligatorSwift encoded public key.
    ///
    /// # Returns
    ///
    /// `Ok(Handshake<ReceivedKey>)` - Ready to send version packet with derived session keys.
    ///
    /// # Errors
    ///
    /// * `V1Protocol` - Remote peer is using the legacy V1 protocol.
    /// * `SecretGeneration` - Failed to derive session keys from ECDH.
    pub fn receive_key(
        self,
        their_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    ) -> Result<Handshake<ReceivedKey<'a>>, Error> {
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
            state: ReceivedKey {
                session_keys,
                local_garbage: self.state.local_garbage,
            },
        })
    }
}

impl<'a> Handshake<ReceivedKey<'a>> {
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

    /// Send garbage terminator, optional decoy packets, and version packet.
    ///
    /// This is the **third state transition** in the handshake process, moving from
    /// `ReceivedKey` to `SentVersion` state. The method initiates encrypted communication
    /// by sending the local garbage terminator followed by encrypted packets.
    ///
    /// # Parameters
    ///
    /// * `output_buffer` - Buffer to write terminator and encrypted packets. Must have
    ///   sufficient capacity as calculated by `send_version_len()`.
    /// * `decoys` - Optional array of decoy packet contents to send before version packet
    ///   to help hide the shape of traffic.
    ///
    /// # Returns
    ///
    /// `Ok(Handshake<SentVersion>)` - Ready to receive and authenticate remote peer's version.
    ///
    /// # Errors
    ///
    /// * `BufferTooSmall` - Output buffer insufficient for terminator + packets.
    /// * `Decryption` - Cipher operation failed.
    pub fn send_version(
        self,
        output_buffer: &mut [u8],
        decoys: Option<&[&[u8]]>,
    ) -> Result<Handshake<SentVersion>, Error> {
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
        let mut aad = self.state.local_garbage;

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

        let version_packet_len = OutboundCipher::encryption_buffer_len(VERSION_CONTENT.len());
        cipher.outbound().encrypt(
            &VERSION_CONTENT,
            &mut output_buffer[bytes_written..bytes_written + version_packet_len],
            PacketType::Genuine,
            aad,
        )?;

        Ok(Handshake {
            network: self.network,
            role: self.role,
            state: SentVersion {
                cipher,
                remote_garbage_terminator,
            },
        })
    }
}

impl Handshake<SentVersion> {
    /// Process remote peer's garbage bytes and locate the garbage terminator.
    ///
    /// This is a critical step in the handshake process, transitioning from
    /// `SentVersion` to `ReceivedGarbage` state. The method searches for the remote peer's
    /// garbage terminator within the input buffer and separates garbage bytes from the
    /// subsequent encrypted packet data.
    ///
    /// # Parameters
    ///
    /// * `input_buffer` - Buffer containing remote peer's garbage bytes followed by encrypted
    ///   packet data. The garbage terminator marks the boundary between these sections.
    ///
    /// # Returns
    ///
    /// * `Ok(GarbageResult::FoundGarbage)` - Successfully located garbage terminator.
    ///   Contains the next handshake state and number of bytes consumed from input buffer.
    /// * `Ok(GarbageResult::NeedMoreData)` - Garbage terminator not found in current buffer.
    ///   More data needed to locate the terminator boundary.
    ///
    /// # Errors
    ///
    /// * `NoGarbageTerminator` - Input exceeds maximum garbage size without finding terminator.
    ///   Indicates protocol violation or potential attack.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bip324::{Handshake, GarbageResult, SentVersion};
    /// # use bip324::{Role, Network};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut handshake = Handshake::new(Network::Bitcoin, Role::Initiator)?;
    /// # // ... complete handshake to SentVersion state ...
    /// # let handshake: Handshake<SentVersion> = todo!();
    ///
    /// let mut network_buffer = Vec::new();
    ///
    /// loop {
    ///     // Read more network data...
    ///     // network_buffer.extend_from_slice(&new_data);
    ///     
    ///     match handshake.receive_garbage(&network_buffer)? {
    ///         GarbageResult::FoundGarbage { handshake: next_state, consumed_bytes } => {
    ///             // Success! Process remaining data for version packets
    ///             let remaining_data = &network_buffer[consumed_bytes..];
    ///             // Continue with next_state.receive_version()...
    ///             break;
    ///         }
    ///         GarbageResult::NeedMoreData(handshake) => {
    ///             // Continue accumulating network data
    ///             continue;
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn receive_garbage<'a>(self, input_buffer: &'a [u8]) -> Result<GarbageResult<'a>, Error> {
        match self.split_garbage(input_buffer) {
            Ok((garbage, _ciphertext)) => {
                let consumed_bytes = garbage.len() + NUM_GARBAGE_TERMINTOR_BYTES;
                let handshake = Handshake {
                    network: self.network,
                    role: self.role,
                    state: ReceivedGarbage {
                        cipher: self.state.cipher,
                        remote_garbage: if garbage.is_empty() {
                            None
                        } else {
                            Some(garbage)
                        },
                    },
                };

                Ok(GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                })
            }
            Err(Error::CiphertextTooSmall) => Ok(GarbageResult::NeedMoreData(self)),
            Err(e) => Err(e),
        }
    }

    /// Split buffer on garbage terminator.
    fn split_garbage<'b>(&self, buffer: &'b [u8]) -> Result<(&'b [u8], &'b [u8]), Error> {
        let terminator = &self.state.remote_garbage_terminator;

        if let Some(index) = buffer
            .windows(terminator.len())
            .position(|window| window == terminator)
        {
            let (garbage, rest) = buffer.split_at(index);
            let ciphertext = &rest[terminator.len()..];
            Ok((garbage, ciphertext))
        } else if buffer.len() >= MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES {
            Err(Error::NoGarbageTerminator)
        } else {
            Err(Error::CiphertextTooSmall)
        }
    }
}

impl<'a> Handshake<ReceivedGarbage<'a>> {
    /// Decrypt the packet length from the encrypted length bytes.
    pub fn decrypt_packet_len(&mut self, length_bytes: [u8; 3]) -> Result<usize, Error> {
        Ok(self.state.cipher.inbound().decrypt_packet_len(length_bytes))
    }

    /// Decrypt and authenticate the next packet to complete the handshake.
    ///
    /// This is the **final state transition** in the handshake process, completing the
    /// BIP-324 protocol by processing the remote peer's version packet. The method performs
    /// in-place decryption of encrypted packet data and determines whether the handshake
    /// is complete or if additional decoy packets need processing.
    ///
    /// # Unique Characteristics
    ///
    /// **Mutable Buffer Requirement**: Unlike other handshake methods, `receive_version()`
    /// requires a mutable input buffer because it performs in-place decryption operations,
    /// modifying ciphertext directly to produce plaintext for memory efficiency.
    ///
    /// # Parameters
    ///
    /// * `input_buffer` - **Mutable** buffer containing encrypted packet data (excluding
    ///   the 3-byte length prefix). The ciphertext will be overwritten with plaintext
    ///   during decryption. Buffer size must match the decrypted packet length.
    ///
    /// # Returns
    ///
    /// * `Ok(VersionResult::Complete { cipher })` - Handshake completed successfully.
    ///   The returned `CipherSession` is ready for secure message exchange.
    /// * `Ok(VersionResult::Decoy(handshake))` - Packet was a decoy, continue processing
    ///   with the returned handshake state for the next packet.
    ///
    /// # Errors
    ///
    /// * `Decryption` - Packet authentication failed or ciphertext is malformed.
    /// * `CiphertextTooSmall` - Ciphertext argument does not contain a whole packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use bip324::{Handshake, VersionResult, ReceivedGarbage, NUM_LENGTH_BYTES};
    /// # use bip324::{Role, Network};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut handshake = Handshake::new(Network::Bitcoin, Role::Initiator)?;
    /// # // ... complete handshake to ReceivedGarbage state ...
    /// # let mut handshake: Handshake<ReceivedGarbage> = todo!();
    /// # let encrypted_data: &[u8] = todo!();
    ///
    /// let mut remaining_data = encrypted_data;
    ///
    /// // Process packets until version packet found
    /// loop {
    ///     // Read packet length (first 3 bytes)
    ///     let packet_len = handshake.decrypt_packet_len(
    ///         remaining_data[..NUM_LENGTH_BYTES].try_into()?
    ///     )?;
    ///     
    ///     // Extract packet data (excluding length prefix)
    ///     let mut packet = remaining_data[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    ///     remaining_data = &remaining_data[NUM_LENGTH_BYTES + packet_len..];
    ///     
    ///     // Process the packet
    ///     match handshake.receive_version(&mut packet)? {
    ///         VersionResult::Complete { cipher } => {
    ///             // Handshake complete! Ready for secure messaging
    ///             break;
    ///         }
    ///         VersionResult::Decoy(next_handshake) => {
    ///             // Decoy packet processed, continue with next packet
    ///             handshake = next_handshake;
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn receive_version(mut self, input_buffer: &mut [u8]) -> Result<VersionResult<'a>, Error> {
        // Take the garbage on first call to ensure AAD is only used once.
        let aad = self.state.remote_garbage.take();

        let (packet_type, _) = self
            .state
            .cipher
            .inbound()
            .decrypt_in_place(input_buffer, aad)?;

        match packet_type {
            PacketType::Genuine => Ok(VersionResult::Complete {
                cipher: self.state.cipher,
            }),
            PacketType::Decoy => Ok(VersionResult::Decoy(self)),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::vec;

    use crate::NUM_LENGTH_BYTES;

    use super::*;

    // Test that the handshake completes successfully with garbage and decoy packets
    // from both parties. This is a comprehensive integration test of the full protocol.
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

        let resp_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();

        // Send responder key + garbage.
        let mut resp_buffer =
            vec![0u8; Handshake::<Initialized>::send_key_len(Some(&responder_garbage))];
        let resp_handshake = resp_handshake
            .send_key(Some(&responder_garbage), &mut resp_buffer)
            .unwrap();

        // Initiator receives responder's key.
        let init_handshake = init_handshake
            .receive_key(resp_buffer[..NUM_ELLIGATOR_SWIFT_BYTES].try_into().unwrap())
            .unwrap();

        // Responder receives initiator's key.
        let resp_handshake = resp_handshake
            .receive_key(init_buffer[..NUM_ELLIGATOR_SWIFT_BYTES].try_into().unwrap())
            .unwrap();

        // Create decoy packets for both sides.
        let init_decoy1 = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let init_decoy2 = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01];
        let init_decoys = vec![init_decoy1.as_slice(), init_decoy2.as_slice()];

        let resp_decoy1 = vec![0xAB, 0xCD, 0xEF];
        let resp_decoys = vec![resp_decoy1.as_slice()];

        // Initiator sends decoys and version.
        let mut init_version_buffer =
            vec![0u8; Handshake::<ReceivedKey<'_>>::send_version_len(Some(&init_decoys))];
        let init_handshake = init_handshake
            .send_version(&mut init_version_buffer, Some(&init_decoys))
            .unwrap();

        // Responder sends decoys and version.
        let mut resp_version_buffer =
            vec![0u8; Handshake::<ReceivedKey<'_>>::send_version_len(Some(&resp_decoys))];
        let resp_handshake = resp_handshake
            .send_version(&mut resp_version_buffer, Some(&resp_decoys))
            .unwrap();

        // Initiator processes responder's response
        let full_resp_message = [&responder_garbage[..], &resp_version_buffer[..]].concat();

        // First, find the garbage terminator
        let (mut init_handshake, consumed) =
            match init_handshake.receive_garbage(&full_resp_message).unwrap() {
                GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                } => (handshake, consumed_bytes),
                GarbageResult::NeedMoreData(_) => panic!("Should have found garbage terminator"),
            };

        // Process the encrypted packets (1 decoy + 1 version)
        let mut remaining = &full_resp_message[consumed..];

        // First packet is a decoy
        let packet_len = init_handshake
            .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
            .unwrap();
        let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
        remaining = &remaining[NUM_LENGTH_BYTES + packet_len..];

        init_handshake = match init_handshake.receive_version(&mut packet).unwrap() {
            VersionResult::Decoy(handshake) => handshake,
            VersionResult::Complete { .. } => panic!("First packet should be decoy"),
        };

        // Second packet is the version
        let packet_len = init_handshake
            .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
            .unwrap();
        let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

        match init_handshake.receive_version(&mut packet).unwrap() {
            VersionResult::Complete { .. } => {} // Success!
            VersionResult::Decoy(_) => panic!("Second packet should be version"),
        };

        // Responder processes initiator's response
        let full_init_message = [&initiator_garbage[..], &init_version_buffer[..]].concat();

        // First, find the garbage terminator
        let (mut resp_handshake, consumed) =
            match resp_handshake.receive_garbage(&full_init_message).unwrap() {
                GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                } => (handshake, consumed_bytes),
                GarbageResult::NeedMoreData(_) => panic!("Should have found garbage terminator"),
            };

        // Process the encrypted packets (2 decoys + 1 version)
        let mut remaining = &full_init_message[consumed..];

        // First two packets are decoys
        for i in 0..2 {
            let packet_len = resp_handshake
                .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
                .unwrap();
            let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
            remaining = &remaining[NUM_LENGTH_BYTES + packet_len..];

            resp_handshake = match resp_handshake.receive_version(&mut packet).unwrap() {
                VersionResult::Decoy(handshake) => handshake,
                VersionResult::Complete { .. } => panic!("Packet {} should be decoy", i),
            };
        }

        // Third packet is the version
        let packet_len = resp_handshake
            .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
            .unwrap();
        let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

        match resp_handshake.receive_version(&mut packet).unwrap() {
            VersionResult::Complete { .. } => {} // Success!
            VersionResult::Decoy(_) => panic!("Third packet should be version"),
        };
    }

    // Test that send_key properly validates garbage length limits (max 4095 bytes)
    // and buffer size requirements.
    #[test]
    fn test_handshake_send_key() {
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

    // Test the NeedMoreData scenario where receive_garbage is called with partial data.
    // The local peer doesn't know how much garbage the remote will send, so just needs
    // to pull and do some buffer mangament.
    #[test]
    fn test_handshake_receive_garbage_buffer() {
        let init_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let resp_handshake =
            Handshake::<Initialized>::new(Network::Bitcoin, Role::Responder).unwrap();

        let mut init_buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let init_handshake = init_handshake.send_key(None, &mut init_buffer).unwrap();

        let mut resp_buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let resp_handshake = resp_handshake.send_key(None, &mut resp_buffer).unwrap();

        let init_handshake = init_handshake
            .receive_key(resp_buffer[..NUM_ELLIGATOR_SWIFT_BYTES].try_into().unwrap())
            .unwrap();
        let resp_handshake = resp_handshake
            .receive_key(init_buffer[..NUM_ELLIGATOR_SWIFT_BYTES].try_into().unwrap())
            .unwrap();

        let mut init_version_buffer =
            vec![0u8; Handshake::<ReceivedKey<'_>>::send_version_len(None)];
        let _init_handshake = init_handshake
            .send_version(&mut init_version_buffer, None)
            .unwrap();

        let mut resp_version_buffer =
            vec![0u8; Handshake::<ReceivedKey<'_>>::send_version_len(None)];
        let resp_handshake = resp_handshake
            .send_version(&mut resp_version_buffer, None)
            .unwrap();

        // Test streaming scenario with receive_garbage
        let partial_data_1 = &init_version_buffer[..1];
        let returned_handshake = match resp_handshake.receive_garbage(partial_data_1).unwrap() {
            GarbageResult::NeedMoreData(handshake) => handshake,
            GarbageResult::FoundGarbage { .. } => {
                panic!("Should have needed more data with 1 byte")
            }
        };

        // Feed a bit more data - still probably not enough.
        let partial_data_2 = &init_version_buffer[..5];
        let returned_handshake = match returned_handshake.receive_garbage(partial_data_2).unwrap() {
            GarbageResult::NeedMoreData(handshake) => handshake,
            GarbageResult::FoundGarbage { .. } => {
                panic!("Should have needed more data with 5 bytes")
            }
        };

        // Now provide enough data to find the garbage terminator.
        // Since there's no garbage, the terminator should be at the beginning.
        let (mut handshake, consumed) = match returned_handshake
            .receive_garbage(&init_version_buffer)
            .unwrap()
        {
            GarbageResult::FoundGarbage {
                handshake,
                consumed_bytes,
            } => (handshake, consumed_bytes),
            GarbageResult::NeedMoreData(_) => {
                panic!("Should have found garbage terminator with full data")
            }
        };

        // Process the version packet
        let remaining = &init_version_buffer[consumed..];
        let packet_len = handshake
            .decrypt_packet_len(remaining[..NUM_LENGTH_BYTES].try_into().unwrap())
            .unwrap();
        let mut packet = remaining[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();

        match handshake.receive_version(&mut packet).unwrap() {
            VersionResult::Complete { .. } => {} // Success!
            VersionResult::Decoy(_) => panic!("Should be version packet"),
        };
    }

    // Test split_garbage error conditions.
    //
    // 1. NoGarbageTerminator - when buffer exceeds max size without finding terminator
    // 2. CiphertextTooSmall - when buffer is too short to possibly contain terminator
    #[test]
    fn test_handshake_split_garbage() {
        // Create a handshake and bring it to the SentVersion state to test split_garbage
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let mut buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
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

    // Test that receive_key detects V1 protocol when peer's key starts with network magic.
    #[test]
    fn test_v1_protocol_detection() {
        // Test that receive_key properly detects V1 protocol magic bytes
        let handshake = Handshake::<Initialized>::new(Network::Bitcoin, Role::Initiator).unwrap();
        let mut buffer = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let handshake = handshake.send_key(None, &mut buffer).unwrap();

        // Create a key that starts with Bitcoin mainnet magic bytes
        let mut v1_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        v1_key[..4].copy_from_slice(&Network::Bitcoin.magic().to_bytes());

        let result = handshake.receive_key(v1_key);
        assert!(matches!(result, Err(Error::V1Protocol)));

        // Test with different networks
        let handshake = Handshake::<Initialized>::new(Network::Testnet, Role::Responder).unwrap();
        let handshake = handshake.send_key(None, &mut buffer).unwrap();

        let mut v1_testnet_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        v1_testnet_key[..4].copy_from_slice(&Network::Testnet.magic().to_bytes());

        let result = handshake.receive_key(v1_testnet_key);
        assert!(matches!(result, Err(Error::V1Protocol)));
    }
}
