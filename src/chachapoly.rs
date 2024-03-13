use crate::chacha::ChaCha20;
use crate::error;
use error::ChaCha20Poly1305EncryptionError;
use crate::poly1305::Poly1305;
extern crate alloc;
pub use error::ChaCha20Poly1305DecryptionError;

#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl ChaCha20Poly1305 {
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        ChaCha20Poly1305 { key, nonce }
    }

    pub fn encrypt<'a>(self, plaintext: &'a mut [u8], aad: Option<&'a [u8]>, buffer: &'a mut [u8]) -> Result<&'a [u8], ChaCha20Poly1305EncryptionError> {
        if plaintext.len() + 16 != buffer.len() {
            return Err(ChaCha20Poly1305EncryptionError::IncorrectBuffer("The buffer provided was incorrect. Ensure the buffer is 16 bytes longer than the message.".to_string()));
        }
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
        chacha.apply_keystream(plaintext);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(keystream[..32].try_into().expect("32 is a valid subset of 64."));
        let aad = aad.unwrap_or(&[]);
        poly.add(aad);
        poly.add(plaintext);
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

    pub fn decrypt<'a>(self, ciphertext: &'a mut [u8], aad: Option<&'a [u8]>) -> Result<&'a [u8], ChaCha20Poly1305DecryptionError> {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 0);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(keystream[..32].try_into().expect("32 is a valid subset of 64."));
        let aad = aad.unwrap_or(&[]);
        if ciphertext.len() >= 16 {
            let (received_msg, received_tag) = ciphertext.split_at_mut(ciphertext.len()- 16);
            poly.add(aad);
            poly.add(received_msg);
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
                Err(ChaCha20Poly1305DecryptionError::UnauthenticatedAdditionalData("Computed tag did not match.".to_string()))
            }
        } else {
            Err(ChaCha20Poly1305DecryptionError::CiphertextTooShort("Ciphertext must be at least 16 bytes.".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{AeadInPlace, KeyInit, Nonce};

    #[test]
    fn test_encrypt_other_with_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key: [u8; 32] = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"Some 17 bytes!!!!".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).expect("Key is valid.");
        other.encrypt_in_place(conformed_nonce, &aad, &mut message).unwrap();
        let mut message2 = *b"Cryptographic Forum Research Group";
        let mut aad = *b"Some 17 bytes!!!!";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 50];
        us.encrypt(message2.as_mut_slice(), Some(aad.as_mut_slice()), buffer.as_mut_slice()).unwrap();
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_encrypt_other_no_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other.encrypt_in_place(conformed_nonce, &aad, &mut message).unwrap();
        let mut message2 = *b"Cryptographic Forum Research Group";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 50];
        us.encrypt(message2.as_mut_slice(), None, buffer.as_mut_slice()).unwrap();
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_encrypt_other_no_content() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"".to_vec();
        let aad = b"Some secret".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other.encrypt_in_place(conformed_nonce, &aad, &mut message).unwrap();
        let mut message2 = *b"";
        let mut aad = *b"Some secret";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 16];
        us.encrypt(message2.as_mut_slice(), Some(aad.as_mut_slice()), buffer.as_mut_slice()).unwrap();
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_decrypt_other_no_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other.encrypt_in_place(conformed_nonce, &aad, &mut message).unwrap();
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let plaintext = us.decrypt(message.as_mut_slice(), None).unwrap();
        let message = b"Cryptographic Forum Research Group".to_vec();
        assert_eq!(hex::encode(message), hex::encode(plaintext))
    }

    #[test]
    fn test_decrypt_other_no_content() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"".to_vec();
        let aad = b"Cryptographic Forum Research Group".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other.encrypt_in_place(conformed_nonce, &aad, &mut message).unwrap();
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let aad = *b"Cryptographic Forum Research Group";
        let plaintext = us.decrypt(message.as_mut_slice(), Some(&aad)).unwrap();
        assert!(plaintext.len() == 0);
    }
}