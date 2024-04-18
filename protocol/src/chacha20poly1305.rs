pub(crate) mod chacha20;
mod poly1305;

use chacha20::ChaCha20;
use poly1305::Poly1305;

use alloc::fmt;

/// Zero array for padding slices.
const ZEROES: [u8; 16] = [0u8; 16];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnauthenticatedAdditionalData,
    CiphertextTooShort,
    IncorrectBuffer,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnauthenticatedAdditionalData => write!(f, "Unauthenticated aad."),
            Error::CiphertextTooShort => write!(f, "Ciphertext must be at least 16 bytes."),
            Error::IncorrectBuffer => write!(f, "The buffer provided was incorrect. Ensure the buffer is 16 bytes longer than the message."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::UnauthenticatedAdditionalData => None,
            Error::CiphertextTooShort => None,
            Error::IncorrectBuffer => None,
        }
    }
}

#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl ChaCha20Poly1305 {
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        ChaCha20Poly1305 { key, nonce }
    }

    /// Encrypt content in place and return the poly1305 16-byte authentication code.
    pub fn encrypt<'a>(
        self,
        content: &'a mut [u8],
        aad: Option<&'a [u8]>,
    ) -> Result<[u8; 16], Error> {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
        chacha.apply_keystream(content);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(
            keystream[..32]
                .try_into()
                .expect("32 is a valid subset of 64."),
        );
        let aad = aad.unwrap_or(&[]);
        // AAD and ciphertext are padded if not 16-byte aligned.
        poly.add(aad);
        let aad_overflow = aad.len() % 16;
        if aad_overflow > 0 {
            poly.add(&ZEROES[0..(16 - aad_overflow)]);
        }

        poly.add(content);
        let text_overflow = content.len() % 16;
        if text_overflow > 0 {
            poly.add(&ZEROES[0..(16 - text_overflow)]);
        }

        let aad_len = aad.len().to_le_bytes();
        let msg_len = content.len().to_le_bytes();
        let mut len_buffer = [0u8; 16];
        len_buffer[..aad_len.len()].copy_from_slice(&aad_len[..]);
        for i in 0..msg_len.len() {
            len_buffer[i + aad_len.len()] = msg_len[i]
        }
        poly.add(&len_buffer);

        Ok(poly.tag())
    }

    /// Decrypt the ciphertext in place if authentication tag is correct.
    pub fn decrypt<'a>(
        self,
        ciphertext: &'a mut [u8],
        tag: [u8; 16],
        aad: Option<&'a [u8]>,
    ) -> Result<(), Error> {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 0);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(
            keystream[..32]
                .try_into()
                .expect("32 is a valid subset of 64."),
        );
        let aad = aad.unwrap_or(&[]);
        if ciphertext.len() >= 16 {
            poly.add(aad);
            // AAD and ciphertext are padded if not 16-byte aligned.
            let aad_overflow = aad.len() % 16;
            if aad_overflow > 0 {
                poly.add(&ZEROES[0..(16 - aad_overflow)]);
            }
            poly.add(&ciphertext);
            let msg_overflow = ciphertext.len() % 16;
            if msg_overflow > 0 {
                poly.add(&ZEROES[0..(16 - msg_overflow)]);
            }

            let aad_len = aad.len().to_le_bytes();
            let msg_len = received_msg.len().to_le_bytes();
            let mut len_buffer = [0u8; 16];
            len_buffer[..aad_len.len()].copy_from_slice(&aad_len[..]);
            for i in 0..msg_len.len() {
                len_buffer[i + aad_len.len()] = msg_len[i]
            }
            poly.add(&len_buffer);
            let derived_tag = poly.tag();
            if derived_tag.eq(&tag) {
                let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
                chacha.apply_keystream(ciphertext);
                Ok(())
            } else {
                Err(Error::UnauthenticatedAdditionalData)
            }
        } else {
            Err(Error::CiphertextTooShort)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use hex::prelude::*;

    #[test]
    fn test_rfc7539() {
        let mut message = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = Vec::from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let key: [u8; 32] =
            Vec::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = Vec::from_hex("070000004041424344454647")
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let cipher = ChaCha20Poly1305::new(key, nonce);
        let tag = cipher.encrypt(&mut message, Some(&aad)).unwrap();

        let mut buffer = [0u8; 130];
        buffer[..message.len()].copy_from_slice(&message);
        buffer[message.len()..].copy_from_slice(&tag);
        assert_eq!(&buffer.to_lower_hex_string(), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    }
}
