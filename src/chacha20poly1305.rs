mod chacha20;
mod poly1305;

use crate::error;
pub(crate) use chacha20::ChaCha20;
use poly1305::Poly1305;

use error::ChaCha20Poly1305DecryptionError;
use error::ChaCha20Poly1305EncryptionError;

use alloc::string::ToString;

// Zero array for padding slices.
const ZEROES: [u8; 16] = [0u8; 16];

#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl ChaCha20Poly1305 {
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        ChaCha20Poly1305 { key, nonce }
    }

    pub fn encrypt<'a>(
        self,
        plaintext: &'a mut [u8],
        aad: Option<&'a [u8]>,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ChaCha20Poly1305EncryptionError> {
        if plaintext.len() + 16 != buffer.len() {
            return Err(ChaCha20Poly1305EncryptionError::IncorrectBuffer("The buffer provided was incorrect. Ensure the buffer is 16 bytes longer than the message.".to_string()));
        }
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
        chacha.apply_keystream(plaintext);
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

        poly.add(plaintext);
        let text_overflow = plaintext.len() % 16;
        if text_overflow > 0 {
            poly.add(&ZEROES[0..(16 - text_overflow)]);
        }

        let aad_len = aad.len().to_le_bytes();
        let msg_len = plaintext.len().to_le_bytes();
        let mut len_buffer = [0u8; 16];
        len_buffer[..aad_len.len()].copy_from_slice(&aad_len[..]);
        for i in 0..msg_len.len() {
            len_buffer[i + aad_len.len()] = msg_len[i]
        }
        poly.add(&len_buffer);
        let tag = poly.tag();
        for i in 0..plaintext.len() {
            if i < plaintext.len() {
                buffer[i] = plaintext[i]
            }
        }
        for i in 0..tag.len() {
            if i < tag.len() {
                buffer[plaintext.len() + i] = tag[i]
            }
        }
        Ok(&buffer[..plaintext.len() + tag.len()])
    }

    pub fn decrypt<'a>(
        self,
        ciphertext: &'a mut [u8],
        aad: Option<&'a [u8]>,
    ) -> Result<&'a [u8], ChaCha20Poly1305DecryptionError> {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 0);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(
            keystream[..32]
                .try_into()
                .expect("32 is a valid subset of 64."),
        );
        let aad = aad.unwrap_or(&[]);
        if ciphertext.len() >= 16 {
            let (received_msg, received_tag) = ciphertext.split_at_mut(ciphertext.len() - 16);
            poly.add(aad);
            // AAD and ciphertext are padded if not 16-byte aligned.
            let aad_overflow = aad.len() % 16;
            if aad_overflow > 0 {
                poly.add(&ZEROES[0..(16 - aad_overflow)]);
            }
            poly.add(received_msg);
            let msg_overflow = received_msg.len() % 16;
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
            let tag = poly.tag();
            if tag.eq(received_tag) {
                let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
                chacha.apply_keystream(received_msg);
                Ok(received_msg)
            } else {
                Err(
                    ChaCha20Poly1305DecryptionError::UnauthenticatedAdditionalData(
                        "Computed tag did not match.".to_string(),
                    ),
                )
            }
        } else {
            Err(ChaCha20Poly1305DecryptionError::CiphertextTooShort(
                "Ciphertext must be at least 16 bytes.".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7539() {
        let mut message = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647")
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let mut buffer = [0u8; 130];
        let cipher = ChaCha20Poly1305::new(key, nonce);
        cipher
            .encrypt(message.as_mut_slice(), Some(&aad), buffer.as_mut_slice())
            .unwrap();

        assert_eq!(hex::encode(&buffer), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    }
}
