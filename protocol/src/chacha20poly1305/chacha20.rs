// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ChaCha20 stream cipher based on RFC7539.

/// The first four words (32-bit) of the ChaCha stream cipher state are constants.
const WORD_1: u32 = 0x61707865;
const WORD_2: u32 = 0x3320646e;
const WORD_3: u32 = 0x79622d32;
const WORD_4: u32 = 0x6b206574;

/// Each quarter round of ChaCha scrambles 4 words (32-bit) of the state
/// using some Addition (mod 2^32), Rotation, and XOR (ARX). 8 quarter
/// rounds make up a round. A block is broken up into 16 32-bit words
/// and each quarter round takes 4 words as input.
const CHACHA_ROUND_INDICIES: [(usize, usize, usize, usize); 8] = [
    // The first 4 rounds are rows of a 4x4 matrix
    // of the block broken up into 32-bit words.
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
    // The first 4 rounds are diagonals of a 4x4 matrix
    // of the block broken up into 32-bit words.
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
];

/// The cipher's block size is 64 bytes.
const CHACHA_BLOCKSIZE: usize = 64;

/// The ChaCha20 stream cipher.
#[derive(Debug)]
pub(crate) struct ChaCha20 {
    /// A 256 bit secret session key shared by the parties communitcating.
    key: [u8; 32],
    /// A 96 bit initialization vector (IV), or nonce. A key/nonce pair should only be used once.  
    nonce: [u8; 12],
    /// Internal block index of keystream.
    block_count: u32,
    /// Interal byte offset index of the block_count.
    seek_offset_bytes: usize,
}

impl ChaCha20 {
    /// Make a new instance of ChaCha20 from an index in the keystream.
    pub fn new(key: [u8; 32], nonce: [u8; 12], seek: u32) -> Self {
        let block_count = seek / 64;
        let seek_offset_bytes = (seek % 64) as usize;
        ChaCha20 {
            key,
            nonce,
            block_count,
            seek_offset_bytes,
        }
    }

    /// Make a new instance of ChaCha20 from a block in the keystream.
    pub fn new_from_block(key: [u8; 32], nonce: [u8; 12], block: u32) -> Self {
        ChaCha20 {
            key,
            nonce,
            block_count: block,
            seek_offset_bytes: 0,
        }
    }

    /// Apply the keystream to a message.
    pub fn apply_keystream(&mut self, to: &mut [u8]) {
        let num_full_blocks = to.len() / CHACHA_BLOCKSIZE;
        let mut j = 0;
        while j < num_full_blocks {
            let kstream = keystream_at_slice(
                self.key,
                self.nonce,
                self.block_count,
                self.seek_offset_bytes,
            );
            for (c, k) in to[j * CHACHA_BLOCKSIZE..(j + 1) * CHACHA_BLOCKSIZE]
                .iter_mut()
                .zip(kstream.iter())
            {
                *c ^= *k
            }
            j += 1;
            self.block_count += 1;
        }
        if to.len() % 64 > 0 {
            let kstream = keystream_at_slice(
                self.key,
                self.nonce,
                self.block_count,
                self.seek_offset_bytes,
            );
            for (c, k) in to[j * CHACHA_BLOCKSIZE..].iter_mut().zip(kstream.iter()) {
                *c ^= *k
            }
            self.block_count += 1;
        }
    }

    /// Get the keystream block at a specified block.
    pub(crate) fn get_keystream(&mut self, block: u32) -> [u8; 64] {
        self.block(block);
        keystream_at_slice(
            self.key,
            self.nonce,
            self.block_count,
            self.seek_offset_bytes,
        )
    }

    /// Update the index of the keystream to the given byte.
    pub(crate) fn seek(&mut self, seek: u32) {
        self.block_count = seek / 64;
        self.seek_offset_bytes = (seek % 64) as usize;
    }

    /// Update the index of the keystream to a block.
    pub(crate) fn block(&mut self, block: u32) {
        self.block_count = block;
        self.seek_offset_bytes = 0;
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn double_round(state: &mut [u32; 16]) {
    for (a, b, c, d) in CHACHA_ROUND_INDICIES {
        quarter_round(state, a, b, c, d);
    }
}

fn chacha_block(state: &mut [u32; 16]) {
    let initial_state = *state;
    for _ in 0..10 {
        double_round(state)
    }
    for (modified, initial) in state.iter_mut().zip(initial_state.iter()) {
        *modified = modified.wrapping_add(*initial)
    }
}

fn prepare_state(key: [u8; 32], nonce: [u8; 12], count: u32) -> [u32; 16] {
    let mut state: [u32; 16] = [0; 16];
    state[0] = WORD_1;
    state[1] = WORD_2;
    state[2] = WORD_3;
    state[3] = WORD_4;
    state[4] = u32::from_le_bytes(
        key[0..4]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[5] = u32::from_le_bytes(
        key[4..8]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[6] = u32::from_le_bytes(
        key[8..12]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[7] = u32::from_le_bytes(
        key[12..16]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[8] = u32::from_le_bytes(
        key[16..20]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[9] = u32::from_le_bytes(
        key[20..24]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[10] = u32::from_le_bytes(
        key[24..28]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[11] = u32::from_le_bytes(
        key[28..32]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[12] = count;
    state[13] = u32::from_le_bytes(
        nonce[0..4]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[14] = u32::from_le_bytes(
        nonce[4..8]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state[15] = u32::from_le_bytes(
        nonce[8..12]
            .try_into()
            .expect("infalliable conversion to 4 byte array"),
    );
    state
}

fn keystream_from_state(state: &mut [u32; 16]) -> [u8; 64] {
    let mut keystream: [u8; 64] = [0; 64];
    let mut index = 0;
    for &element in state.iter() {
        let bytes = element.to_le_bytes();
        keystream[index..index + 4].copy_from_slice(&bytes);
        index += 4;
    }
    keystream
}

fn keystream_at_slice(key: [u8; 32], nonce: [u8; 12], count: u32, seek: usize) -> [u8; 64] {
    let mut keystream: [u8; 128] = [0; 128];
    let mut state = prepare_state(key, nonce, count);
    chacha_block(&mut state);
    let first_half = keystream_from_state(&mut state);
    let mut state = prepare_state(key, nonce, count + 1);
    chacha_block(&mut state);
    let second_half = keystream_from_state(&mut state);
    keystream[..64].copy_from_slice(&first_half);
    keystream[64..].copy_from_slice(&second_half);
    let kstream: [u8; 64] = keystream[seek..seek + 64].try_into().expect("infallable");
    kstream
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use hex::prelude::*;
    #[cfg(feature = "std")]
    use rand::Rng;

    #[test]
    fn test_quater_round() {
        let a: u32 = 0x11111111;
        let b: u32 = 0x01020304;
        let c: u32 = 0x9b8d6f43;
        let d: u32 = 0x01234567;
        let mut state = [a, b, c, d, a, b, c, d, a, b, c, d, a, b, c, d];
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0].to_be_bytes().to_lower_hex_string(), "ea2a92f4");
        assert_eq!(state[1].to_be_bytes().to_lower_hex_string(), "cb1cf8ce");
        assert_eq!(state[2].to_be_bytes().to_lower_hex_string(), "4581472e");
        assert_eq!(state[3].to_be_bytes().to_lower_hex_string(), "5881c4bb");
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_quater_round_on_block() {
        let a: u32 = 0x879531e0;
        let b: u32 = 0xc5ecf37d;
        let c: u32 = 0x516461b1;
        let d: u32 = 0xc9a62f8a;
        let e: u32 = 0x44c20ef3;
        let f: u32 = 0x3390af7f;
        let g: u32 = 0xd9fc690b;
        let h: u32 = 0x2a5f714c;
        let i: u32 = 0x53372767;
        let j: u32 = 0xb00a5631;
        let k: u32 = 0x974c541a;
        let l: u32 = 0x359e9963;
        let m: u32 = 0x5c971061;
        let n: u32 = 0x3d631689;
        let o: u32 = 0x2098d9d6;
        let p: u32 = 0x91dbd320;
        let mut state = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p];
        quarter_round(&mut state, 2, 7, 8, 13);
        assert_eq!(state[2].to_be_bytes().to_lower_hex_string(), "bdb886dc");
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_block_fn() {
        let a: u32 = 0x61707865;
        let b: u32 = 0x3320646e;
        let c: u32 = 0x79622d32;
        let d: u32 = 0x6b206574;
        let e: u32 = 0x03020100;
        let f: u32 = 0x07060504;
        let g: u32 = 0x0b0a0908;
        let h: u32 = 0x0f0e0d0c;
        let i: u32 = 0x13121110;
        let j: u32 = 0x17161514;
        let k: u32 = 0x1b1a1918;
        let l: u32 = 0x1f1e1d1c;
        let m: u32 = 0x00000001;
        let n: u32 = 0x09000000;
        let o: u32 = 0x4a000000;
        let p: u32 = 0x00000000;
        let mut state = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p];
        chacha_block(&mut state);
        assert_eq!(state[0].to_be_bytes().to_lower_hex_string(), "e4e7f110");
        assert_eq!(state[1].to_be_bytes().to_lower_hex_string(), "15593bd1");
        assert_eq!(state[2].to_be_bytes().to_lower_hex_string(), "1fdd0f50");
        assert_eq!(state[3].to_be_bytes().to_lower_hex_string(), "c47120a3");
        assert_eq!(state[4].to_be_bytes().to_lower_hex_string(), "c7f4d1c7");
        assert_eq!(state[5].to_be_bytes().to_lower_hex_string(), "0368c033");
        assert_eq!(state[6].to_be_bytes().to_lower_hex_string(), "9aaa2204");
        assert_eq!(state[7].to_be_bytes().to_lower_hex_string(), "4e6cd4c3");
        assert_eq!(state[8].to_be_bytes().to_lower_hex_string(), "466482d2");
        assert_eq!(state[9].to_be_bytes().to_lower_hex_string(), "09aa9f07");
        assert_eq!(state[10].to_be_bytes().to_lower_hex_string(), "05d7c214");
        assert_eq!(state[11].to_be_bytes().to_lower_hex_string(), "a2028bd9");
        assert_eq!(state[12].to_be_bytes().to_lower_hex_string(), "d19c12b5");
        assert_eq!(state[13].to_be_bytes().to_lower_hex_string(), "b94e16de");
        assert_eq!(state[14].to_be_bytes().to_lower_hex_string(), "e883d0cb");
        assert_eq!(state[15].to_be_bytes().to_lower_hex_string(), "4e3c50a2");
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_block_serialization() {
        let a: u32 = 0x61707865;
        let b: u32 = 0x3320646e;
        let c: u32 = 0x79622d32;
        let d: u32 = 0x6b206574;
        let e: u32 = 0x03020100;
        let f: u32 = 0x07060504;
        let g: u32 = 0x0b0a0908;
        let h: u32 = 0x0f0e0d0c;
        let i: u32 = 0x13121110;
        let j: u32 = 0x17161514;
        let k: u32 = 0x1b1a1918;
        let l: u32 = 0x1f1e1d1c;
        let m: u32 = 0x00000001;
        let n: u32 = 0x09000000;
        let o: u32 = 0x4a000000;
        let p: u32 = 0x00000000;
        let mut state = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p];
        chacha_block(&mut state);
        assert_eq!(state[7].to_le_bytes().to_lower_hex_string(), "c3d46c4e");
    }

    #[test]
    fn test_prepare_state() {
        let key = Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = Vec::from_hex("000000090000004a00000000").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let count = 1;
        let state = prepare_state(key, nonce, count);
        assert_eq!(state[4].to_be_bytes().to_lower_hex_string(), "03020100");
        assert_eq!(state[10].to_be_bytes().to_lower_hex_string(), "1b1a1918");
        assert_eq!(state[14].to_be_bytes().to_lower_hex_string(), "4a000000");
        assert_eq!(state[15].to_be_bytes().to_lower_hex_string(), "00000000");
        assert_eq!(state[12].to_be_bytes().to_lower_hex_string(), "00000001")
    }

    #[test]
    fn test_small_plaintext() {
        let key = Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = Vec::from_hex("000000090000004a00000000").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let count = 1;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = [8; 3];
        chacha.apply_keystream(&mut binding[..]);
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!([8; 3], binding);
    }

    #[test]
    fn test_modulo_64() {
        let key = Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = Vec::from_hex("000000000000004a00000000").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let count = 1;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = [8; 64];
        chacha.apply_keystream(&mut binding[..]);
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!([8; 64], binding);
    }

    #[test]
    fn test_rfc_standard() {
        let key = Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = Vec::from_hex("000000000000004a00000000").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let count = 64;
        let mut chacha = ChaCha20::new(key, nonce, count);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding.clone();
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], Vec::from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d").unwrap());
        let mut chacha = ChaCha20::new(key, nonce, count);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[test]
    fn test_new_from_block() {
        let key = Vec::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = Vec::from_hex("000000000000004a00000000").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let block: u32 = 1;
        let mut chacha = ChaCha20::new_from_block(key, nonce, block);
        let mut binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let to = binding.clone();
        chacha.apply_keystream(&mut binding[..]);
        assert_eq!(binding[..], Vec::from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d").unwrap());
        chacha.block(block);
        chacha.apply_keystream(&mut binding[..]);
        let binding = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(binding, to);
    }

    #[cfg(feature = "std")]
    fn gen_garbage(garbage_len: u32) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let buffer: Vec<u8> = (0..garbage_len).map(|_| rng.gen()).collect();
        buffer
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_fuzz_other() {
        for _ in 0..100 {
            let garbage_key = gen_garbage(32);
            let key = garbage_key.as_slice().try_into().unwrap();
            let garbage_nonce = gen_garbage(12);
            let nonce = garbage_nonce.as_slice().try_into().unwrap();
            for i in 0..10 {
                let count: u32 = i * 11;
                let mut chacha = ChaCha20::new(key, nonce, count);
                let message = gen_garbage(129);
                let mut message2 = message.clone();
                let msg = &mut message2[..];
                chacha.apply_keystream(msg);
                let mut cipher = ChaCha20::new(key, nonce, 0);
                let mut buffer = message;
                cipher.seek(count);
                cipher.apply_keystream(&mut buffer);
                assert_eq!(buffer.as_slice(), msg);
            }
        }
    }
}
