use alloc::fmt;

use crate::chacha20poly1305::chacha20::ChaCha20;
use crate::chacha20poly1305::ChaCha20Poly1305;

const CHACHA_BLOCKS_USED: u32 = 3;
pub(crate) const REKEY_INTERVAL: u32 = 224;
const REKEY_INITIAL_NONCE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Encryption,
    Decryption,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encryption => write!(f, "Unable to encrypt"),
            Error::Decryption => write!(f, "Unable to dycrypt"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Encryption => None,
            Error::Decryption => None,
        }
    }
}

/// A wrapper over ChaCha20Poly1305 AEAD stream cipher which handles automatically changing
/// nonces and re-keying.
///
/// FSChaCha20Poly1305 is used for message packets in BIP324.
#[derive(Clone, Debug)]
pub struct FSChaCha20Poly1305 {
    key: [u8; 32],
    message_counter: u32,
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
        let counter_div = (self.message_counter / REKEY_INTERVAL).to_le_bytes();
        let counter_mod = (self.message_counter % REKEY_INTERVAL).to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&counter_mod);
        nonce[4..8].copy_from_slice(&counter_div);

        nonce
    }

    /// Increment the message counter and rekey if necessary.
    fn rekey(&mut self, aad: &[u8]) -> Result<(), Error> {
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
                .encrypt(&mut plaintext, Some(&aad))
                .map_err(|_| Error::Encryption)?;
            self.key = plaintext;
        }

        self.message_counter += 1;
        Ok(())
    }

    /// Encrypt the contents in place and return the 16-byte authentication tag.
    pub fn encrypt(&mut self, aad: &[u8], contents: &mut [u8]) -> Result<[u8; 16], Error> {
        let cipher = ChaCha20Poly1305::new(self.key, self.nonce());

        let tag = cipher
            .encrypt(contents, Some(&aad))
            .map_err(|_| Error::Encryption)?;

        self.rekey(aad)?;

        Ok(tag)
    }

    /// Decrypt the contents in place.
    pub fn decrypt(&mut self, aad: &[u8], contents: &mut [u8], tag: [u8; 16]) -> Result<(), Error> {
        let cipher = ChaCha20Poly1305::new(self.key, self.nonce());

        cipher
            .decrypt(contents, tag, Some(aad))
            .map_err(|_| Error::Decryption)?;

        self.rekey(aad)?;

        Ok(())
    }
}

/// A wrapper over ChaCha20 (unauthenticated) stream cipher which handles automatically changing
/// nonces and re-keying.
///
/// FSChaCha20 is used for lengths in BIP324. Should be noted that the lengths are still
/// implicitly authenticated by the message packets.
#[derive(Clone, Debug)]
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

    pub fn crypt(&mut self, chunk: &mut [u8; 3]) -> Result<(), Error> {
        let counter_mod = (self.chunk_counter / REKEY_INTERVAL).to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&counter_mod);
        let mut cipher = ChaCha20::new(self.key, nonce, 0);
        cipher.seek(self.block_counter);
        cipher.apply_keystream(chunk);
        self.block_counter += CHACHA_BLOCKS_USED;
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            let mut key_buffer = [0u8; 32];
            cipher.seek(self.block_counter);
            cipher.apply_keystream(&mut key_buffer);
            self.block_counter = 0;
            self.key = key_buffer;
        }
        self.chunk_counter += 1;
        Ok(())
    }
}
