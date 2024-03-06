use crate::chacha::ChaCha20;
use crate::error;
use error::ChaCha20Poly1305DecryptionError;
use num_bigint::BigUint;

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
    ) -> &'a [u8] {
        let mut chacha = ChaCha20::new_from_block(self.key, self.nonce, 1);
        chacha.apply_keystream(plaintext);
        let keystream = chacha.get_keystream(0);
        let mut poly = Poly1305::new(
            keystream[..32]
                .try_into()
                .expect("32 is a valid subset of 64."),
        );
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
        let tag = poly.get_tag();
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
        &buffer[..plaintext.len() + tag.len()]
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
            poly.add(received_msg);
            let aad_len = aad.len().to_le_bytes();
            let msg_len = received_msg.len().to_le_bytes();
            let mut len_buffer = [0u8; 16];
            len_buffer[..aad_len.len()].copy_from_slice(&aad_len[..]);
            for i in 0..msg_len.len() {
                len_buffer[i + aad_len.len()] = msg_len[i]
            }
            poly.add(&len_buffer);
            let tag = poly.get_tag();
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

#[derive(Debug)]
struct Poly1305 {
    r: BigUint,
    s: BigUint,
    acc: BigUint,
    modulus: BigUint,
}

impl Poly1305 {
    fn new(key: [u8; 32]) -> Self {
        let mut r: [u8; 16] = key[..16]
            .try_into()
            .expect("Key is at least 16 bytes long.");
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
        let r = BigUint::from_bytes_le(&r);
        let s = BigUint::from_bytes_le(&key[16..]);
        let acc = BigUint::from_slice(&[0]);
        let base = BigUint::from_slice(&[2]);
        let modulus = base.pow(130) - BigUint::from_slice(&[5]);
        Poly1305 { r, s, acc, modulus }
    }

    fn add(&mut self, message: &[u8]) {
        let mut i = 0;
        while i < message.len() / 16 {
            let msg_slice = prepare_message_slice(&message[i * 16..(i + 1) * 16]);
            let n = BigUint::from_bytes_le(&msg_slice);
            self.acc = (self.r.clone() * (self.acc.clone() + n))
                .modpow(&BigUint::from_slice(&[1]), &self.modulus);
            i += 1;
        }
        if message.len() % 16 > 0 {
            let msg_slice = prepare_padded_message_slice(&message[i * 16..]);
            let n = BigUint::from_bytes_le(&msg_slice);
            self.acc = (self.r.clone() * (self.acc.clone() + n))
                .modpow(&BigUint::from_slice(&[1]), &self.modulus);
        }
    }

    fn get_tag(self) -> [u8; 16] {
        let tag = self.acc + self.s;
        tag.to_bytes_le()[..16]
            .try_into()
            .expect("Message tag should be at least 16 bytes.")
    }
}

fn prepare_message_slice(msg: &[u8]) -> [u8; 17] {
    let mut fmt_msg = [0u8; 17];
    fmt_msg[..msg.len()].copy_from_slice(msg);
    fmt_msg[msg.len()] = 0x01;
    fmt_msg
}

fn prepare_padded_message_slice(msg: &[u8]) -> [u8; 17] {
    let mut fmt_msg = [0u8; 17];
    fmt_msg[..msg.len()].copy_from_slice(msg);
    fmt_msg[16] = 0x01;
    fmt_msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{AeadInPlace, KeyInit, Nonce};

    #[test]
    fn test_none_message() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let mut poly = Poly1305::new(key);
        let message = b"";
        poly.add(message);
        let _tag = poly.get_tag();
    }

    #[test]
    fn test_encrypt_other_with_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"some".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other
            .encrypt_in_place(conformed_nonce, &aad, &mut message)
            .unwrap();
        let mut message2 = *b"Cryptographic Forum Research Group";
        let mut aad = *b"some";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 50];
        us.encrypt(
            message2.as_mut_slice(),
            Some(aad.as_mut_slice()),
            buffer.as_mut_slice(),
        );
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_encrypt_other_no_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other
            .encrypt_in_place(conformed_nonce, &aad, &mut message)
            .unwrap();
        let mut message2 = *b"Cryptographic Forum Research Group";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 50];
        us.encrypt(message2.as_mut_slice(), None, buffer.as_mut_slice());
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_encrypt_other_no_content() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"".to_vec();
        let aad = b"Some secret".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other
            .encrypt_in_place(conformed_nonce, &aad, &mut message)
            .unwrap();
        let mut message2 = *b"";
        let mut aad = *b"Some secret";
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let mut buffer = [0u8; 16];
        us.encrypt(
            message2.as_mut_slice(),
            Some(aad.as_mut_slice()),
            buffer.as_mut_slice(),
        );
        assert_eq!(hex::encode(message), hex::encode(buffer));
    }

    #[test]
    fn test_decrypt_other_no_aad() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"Cryptographic Forum Research Group".to_vec();
        let aad = b"".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other
            .encrypt_in_place(conformed_nonce, &aad, &mut message)
            .unwrap();
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let plaintext = us.decrypt(message.as_mut_slice(), None).unwrap();
        let message = b"Cryptographic Forum Research Group".to_vec();
        assert_eq!(hex::encode(message), hex::encode(plaintext))
    }

    #[test]
    fn test_decrypt_other_no_content() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .unwrap();
        let key = key.as_slice().try_into().unwrap();
        let nonce = [0u8; 12];
        let mut message = b"".to_vec();
        let aad = b"Cryptographic Forum Research Group".to_vec();
        let conformed_nonce = Nonce::from_slice(&nonce);
        let other = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("Key is valid.");
        other
            .encrypt_in_place(conformed_nonce, &aad, &mut message)
            .unwrap();
        let us = ChaCha20Poly1305::new(key.try_into().unwrap(), nonce);
        let aad = *b"Cryptographic Forum Research Group";
        let plaintext = us.decrypt(message.as_mut_slice(), Some(&aad)).unwrap();
        assert!(plaintext.len() == 0);
    }
}
