// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrap ciphers with automatic re-keying in order to provide [forward secrecy](https://eprint.iacr.org/2001/035.pdf) within a session.
//! Logic is covered by the BIP324 test vectors.

use core::fmt;

use crate::chacha20poly1305::chacha20::ChaCha20;
use crate::chacha20poly1305::ChaCha20Poly1305;

/// Message lengths are encoded in three bytes.
const LENGTH_BYTES: u32 = 3;
/// Ciphers are re-keyed after 224 messages (or chunks).
const REKEY_INTERVAL: u64 = 224;
/// Static four byte prefix used on every re-key.
const REKEY_INITIAL_NONCE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Errors encrypting and decrypting with [`FSChaCha20Poly1305`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Decryption(crate::chacha20poly1305::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption(e) => write!(f, "Unable to dycrypt: {}.", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Decryption(e) => Some(e),
        }
    }
}

/// A wrapper over ChaCha20Poly1305 AEAD stream cipher which handles automatically changing
/// nonces and re-keying, providing forward secrecy within the session.
///
/// FSChaCha20Poly1305 is used for message packets in BIP324.
#[derive(Clone)]
pub struct FSChaCha20Poly1305 {
    key: [u8; 32],
    message_counter: u64,
}

impl FSChaCha20Poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20Poly1305 {
            key,
            message_counter: 0,
        }
    }

    /// Derive current nonce.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        // The 32-bit little-endian encoding of the number of messages with the current key.
        let counter_mod = ((self.message_counter % REKEY_INTERVAL) as u32).to_le_bytes();
        nonce[0..4].copy_from_slice(&counter_mod);
        // The 64-bit little-endian encoding of the number of rekeyings performed.
        let counter_div = (self.message_counter / REKEY_INTERVAL).to_le_bytes();
        nonce[4..12].copy_from_slice(&counter_div);

        nonce
    }

    /// Increment the message counter and rekey if necessary.
    fn rekey(&mut self, aad: &[u8]) {
        if (self.message_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = [0u8; 12];
            rekey_nonce[0..4].copy_from_slice(&REKEY_INITIAL_NONCE);
            rekey_nonce[4..].copy_from_slice(&self.nonce()[4..]);

            let mut plaintext = [0u8; 32];
            let cipher = ChaCha20Poly1305::new(self.key, rekey_nonce);
            cipher.encrypt(&mut plaintext, Some(aad));
            self.key = plaintext;
        }

        self.message_counter += 1;
    }

    /// Encrypt the contents in place and return the 16-byte authentication tag.
    ///
    /// # Arguments
    ///
    /// * `content` - Plaintext to be encrypted in place.
    /// * `aad`     - Optional associated authenticated data covered by the authentication tag.
    ///
    /// # Returns
    ///
    /// The 16-byte authentication tag.
    pub fn encrypt(&mut self, aad: &[u8], content: &mut [u8]) -> [u8; 16] {
        let cipher = ChaCha20Poly1305::new(self.key, self.nonce());

        let tag = cipher.encrypt(content, Some(aad));

        self.rekey(aad);

        tag
    }

    /// Decrypt the contents in place.
    ///
    /// # Arguments
    ///
    /// * `content` - Ciphertext to be decrypted in place.
    /// * `tag`     - 16-byte authentication tag.
    /// * `aad`     - Optional associated authenticated data covered by the authentication tag.
    pub fn decrypt(&mut self, aad: &[u8], content: &mut [u8], tag: [u8; 16]) -> Result<(), Error> {
        let cipher = ChaCha20Poly1305::new(self.key, self.nonce());

        cipher
            .decrypt(content, tag, Some(aad))
            .map_err(Error::Decryption)?;

        self.rekey(aad);

        Ok(())
    }
}

/// A wrapper over ChaCha20 (unauthenticated) stream cipher which handles automatically changing
/// nonces and re-keying, providing forward secrecy within the session.
///
/// FSChaCha20 is used for lengths in BIP324. Should be noted that the lengths are still
/// implicitly authenticated by the message packets.
#[derive(Clone)]
pub struct FSChaCha20 {
    key: [u8; 32],
    block_counter: u32,
    chunk_counter: u32,
}

impl FSChaCha20 {
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20 {
            key,
            block_counter: 0,
            chunk_counter: 0,
        }
    }

    /// Encrypt or decrypt the 3-byte length encodings.
    pub fn crypt(&mut self, chunk: &mut [u8; LENGTH_BYTES as usize]) {
        let counter_mod = (self.chunk_counter / REKEY_INTERVAL as u32).to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&counter_mod);
        let mut cipher = ChaCha20::new(self.key, nonce, 0);
        cipher.seek(self.block_counter);
        cipher.apply_keystream(chunk);
        self.block_counter += LENGTH_BYTES;
        if (self.chunk_counter + 1) % REKEY_INTERVAL as u32 == 0 {
            let mut key_buffer = [0u8; 32];
            cipher.seek(self.block_counter);
            cipher.apply_keystream(&mut key_buffer);
            self.block_counter = 0;
            self.key = key_buffer;
        }
        self.chunk_counter += 1;
    }
}
