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

/// Handshake state-machine to establish the secret material in the communication channel.
///
/// A handshake is first initialized to create local materials needed to setup communication
/// channel between an *initiator* and a *responder*. The next step is to call `complete_materials`
/// no matter if initiator or responder, however the responder should already have the
/// necessary materials from their peers request. `complete_materials` creates the response
/// packet to be sent from each peer and `authenticate_garbage_and_version` is then used
/// to verify the handshake. Finally, the `finalized` method is used to consumer the handshake
/// and return a cipher session for further communication on the channel.
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
    /// Cipher session output.
    cipher_session: Option<CipherSession>,
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
    /// * `buffer` - Packet buffer to send to peer which will include initial materials for handshake + garbage.
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
    /// * `buffer` - Packet buffer to send to peer which will include initial materials for handshake + garbage.
    /// * `rng` - Supplied Random Number Generator.
    /// * `curve` - Supplied secp256k1 context.
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
        if garbage
            .as_ref()
            .map_or(false, |g| g.len() > MAX_NUM_GARBAGE_BYTES)
        {
            return Err(Error::TooMuchGarbage);
        };

        let mut secret_key_buffer = [0u8; 32];
        rng.fill(&mut secret_key_buffer[..]);
        let sk = SecretKey::from_slice(&secret_key_buffer)?;
        let pk = PublicKey::from_secret_key(curve, &sk);
        let es = ElligatorSwift::from_pubkey(pk);

        let point = EcdhPoint {
            secret_key: sk,
            elligator_swift: es,
        };

        // Bounds check on the output buffer.
        let required_bytes = garbage.map_or(NUM_ELLIGATOR_SWIFT_BYTES, |g| {
            NUM_ELLIGATOR_SWIFT_BYTES + g.len()
        });
        if buffer.len() < required_bytes {
            return Err(Error::BufferTooSmall { required_bytes });
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
            cipher_session: None,
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
    /// * `decoys` - Contents for decoy packets sent before version packet.
    ///
    /// # Errors
    ///
    /// * `V1Protocol` - The remote is communicating on the V1 protocol instead of V2. Caller can fallback
    ///   to V1 if they want.
    pub fn complete_materials(
        &mut self,
        their_elliswift: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
        response_buffer: &mut [u8],
        decoys: Option<&[&[u8]]>,
    ) -> Result<(), Error> {
        // Short circuit if the remote is sending the V1 protocol network bytes.
        // Gives the caller an opportunity to fallback to V1 if they choose.
        if self.network.magic()
            == bitcoin::p2p::Magic::from_bytes(
                their_elliswift[..4]
                    .try_into()
                    .expect("64 byte array to have 4 byte prefix"),
            )
        {
            return Err(Error::V1Protocol);
        }

        let theirs = ElligatorSwift::from_array(their_elliswift);

        // Check if the buffer is large enough for the garbage terminator.
        if response_buffer.len() < NUM_GARBAGE_TERMINTOR_BYTES {
            return Err(Error::BufferTooSmall {
                required_bytes: NUM_GARBAGE_TERMINTOR_BYTES,
            });
        }

        // Line up appropriate materials based on role and some
        // garbage terminator haggling.
        let materials = match self.role {
            Role::Initiator => {
                let materials = SessionKeyMaterial::from_ecdh(
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
                let materials = SessionKeyMaterial::from_ecdh(
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

        let mut cipher_session = CipherSession::new(materials, self.role);
        let mut start_index = NUM_GARBAGE_TERMINTOR_BYTES;

        // Write any decoy packets and then the version packet.
        // The first packet, no matter if decoy or genuinie version packet, needs
        // to authenticate the garbage previously sent.
        if let Some(decoys) = decoys {
            for (i, decoy) in decoys.iter().enumerate() {
                let end_index = start_index + OutboundCipher::encryption_buffer_len(decoy.len());
                cipher_session.outbound().encrypt(
                    decoy,
                    &mut response_buffer[start_index..end_index],
                    PacketType::Decoy,
                    if i == 0 { self.garbage } else { None },
                )?;

                start_index = end_index;
            }
        }

        cipher_session.outbound().encrypt(
            &VERSION_CONTENT,
            &mut response_buffer[start_index
                ..start_index + OutboundCipher::encryption_buffer_len(VERSION_CONTENT.len())],
            PacketType::Genuine,
            if decoys.is_none() { self.garbage } else { None },
        )?;

        self.cipher_session = Some(cipher_session);

        Ok(())
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
    /// * `buffer` - Should contain all garbage, the garbage terminator, any decoy packets, and finally the version packet received from peer.
    /// * `packet_buffer` - Required memory allocation for decrypting decoy and version packets.
    ///
    /// # Error    
    ///
    /// * `CiphertextTooSmall` - The buffer did not contain all required information and should be extended (e.g. read more off a socket) and authentication re-tried.
    /// * `BufferTooSmall` - The supplied packet_buffer is not large enough for decrypting the decoy and version packets.
    /// * `HandshakeOutOfOrder` - The handshake sequence is in a bad state and should be restarted.
    /// * `MaxGarbageLength` - Buffer did not contain the garbage terminator, should not be retried.
    pub fn authenticate_garbage_and_version(
        &mut self,
        buffer: &[u8],
        packet_buffer: &mut [u8],
    ) -> Result<(), Error> {
        // Find the end of the garbage.
        let (garbage, ciphertext) = self.split_garbage(buffer)?;

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
        let cipher_session = self
            .cipher_session
            .as_mut()
            .ok_or(Error::HandshakeOutOfOrder)?;

        if self.current_packet_length_bytes.is_none() {
            // Bounds check on the input buffer.
            if ciphertext.len() < self.current_buffer_index + NUM_LENGTH_BYTES {
                return Err(Error::CiphertextTooSmall);
            }
            let packet_length = cipher_session.inbound().decrypt_packet_len(
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
        let packet_type = cipher_session.inbound().decrypt(
            &ciphertext[self.current_buffer_index + NUM_LENGTH_BYTES
                ..self.current_buffer_index + NUM_LENGTH_BYTES + packet_length],
            packet_buffer,
            garbage,
        )?;

        // Mark current decryption point in the buffer.
        self.current_buffer_index = self.current_buffer_index + NUM_LENGTH_BYTES + packet_length;
        self.current_packet_length_bytes = None;

        Ok(matches!(packet_type, PacketType::Genuine))
    }

    /// Complete the handshake and return the cipher session for further communication.
    ///
    /// # Error    
    ///
    /// * `HandshakeOutOfOrder` - The handshake sequence is in a bad state and should be restarted.
    pub fn finalize(self) -> Result<CipherSession, Error> {
        let cipher_session = self.cipher_session.ok_or(Error::HandshakeOutOfOrder)?;
        Ok(cipher_session)
    }

    /// Split off garbage in the given buffer on the remote garbage terminator.
    ///
    /// # Returns
    ///
    /// A `Result` containing the garbage and the remaining ciphertext not including the terminator.
    ///
    /// # Error
    ///
    /// * `CiphertextTooSmall` - Buffer did not contain a garbage terminator.
    /// * `MaxGarbageLength` - Buffer did not contain the garbage terminator and contains too much garbage, should not be retried.
    fn split_garbage<'b>(&self, buffer: &'b [u8]) -> Result<(&'b [u8], &'b [u8]), Error> {
        let garbage_term = self
            .remote_garbage_terminator
            .ok_or(Error::HandshakeOutOfOrder)?;
        if let Some(index) = buffer
            .windows(garbage_term.len())
            .position(|window| window == garbage_term)
        {
            Ok((&buffer[..index], &buffer[(index + garbage_term.len())..]))
        } else if buffer.len() >= (MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES) {
            Err(Error::NoGarbageTerminator)
        } else {
            // Terminator not found, the buffer needs more information.
            Err(Error::CiphertextTooSmall)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use bitcoin::secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
    use core::str::FromStr;
    use hex::prelude::*;
    use std::{string::ToString, vec};

    use super::*;

    #[test]
    fn test_initial_message() {
        let mut message = [0u8; 64];
        let handshake =
            Handshake::new(Network::Bitcoin, Role::Initiator, None, &mut message).unwrap();
        let message = message.to_lower_hex_string();
        let es = handshake.point.elligator_swift.to_string();
        assert!(message.contains(&es))
    }

    #[test]
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
    fn test_shared_secret() {
        // Test that SessionKeyMaterial::from_ecdh produces expected garbage terminators
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
        // Just verify the garbage terminators which are the only public fields we need
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
    fn test_handshake_garbage_length_check() {
        let mut rng = rand::thread_rng();
        let curve = Secp256k1::new();
        let mut handshake_buffer = [0u8; NUM_ELLIGATOR_SWIFT_BYTES + MAX_NUM_GARBAGE_BYTES];

        // Test with valid garbage length.
        let valid_garbage = vec![0u8; MAX_NUM_GARBAGE_BYTES];
        let result = Handshake::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            Some(&valid_garbage),
            &mut handshake_buffer,
            &mut rng,
            &curve,
        );
        assert!(result.is_ok());

        // Test with garbage length exceeding MAX_NUM_GARBAGE_BYTES.
        let too_much_garbage = vec![0u8; MAX_NUM_GARBAGE_BYTES + 1];
        let result = Handshake::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            Some(&too_much_garbage),
            &mut handshake_buffer,
            &mut rng,
            &curve,
        );
        assert!(matches!(result, Err(Error::TooMuchGarbage)));

        // Test too small of buffer.
        let buffer_size = NUM_ELLIGATOR_SWIFT_BYTES + valid_garbage.len() - 1;
        let mut too_small_buffer = vec![0u8; buffer_size];
        let result = Handshake::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            Some(&valid_garbage),
            &mut too_small_buffer,
            &mut rng,
            &curve,
        );

        assert!(
            matches!(result, Err(Error::BufferTooSmall { required_bytes }) if required_bytes == NUM_ELLIGATOR_SWIFT_BYTES + valid_garbage.len()),
            "Expected BufferTooSmall with correct size"
        );

        // Test with no garbage.
        let result = Handshake::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            None,
            &mut handshake_buffer,
            &mut rng,
            &curve,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handshake_no_garbage_terminator() {
        let mut handshake_buffer = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut rng = rand::thread_rng();
        let curve = Secp256k1::signing_only();

        let mut handshake = Handshake::new_with_rng(
            Network::Bitcoin,
            Role::Initiator,
            None,
            &mut handshake_buffer,
            &mut rng,
            &curve,
        )
        .expect("Handshake creation should succeed");

        // Skipping material creation and just placing a mock terminator.
        handshake.remote_garbage_terminator = Some([0xFF; NUM_GARBAGE_TERMINTOR_BYTES]);

        // Test with a buffer that is too long.
        let test_buffer = vec![0; MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES];
        let result = handshake.split_garbage(&test_buffer);
        assert!(matches!(result, Err(Error::NoGarbageTerminator)));

        // Test with a buffer that's just short of the required length.
        let short_buffer = vec![0; MAX_NUM_GARBAGE_BYTES + NUM_GARBAGE_TERMINTOR_BYTES - 1];
        let result = handshake.split_garbage(&short_buffer);
        assert!(matches!(result, Err(Error::CiphertextTooSmall)));
    }
}
