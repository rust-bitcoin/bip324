//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//!
//! The interface is limited to the BIP324 use case for now. This
//! includes hardcoding to the SHA256 hash implementation, as well
//! as requiring an extract step.

use bitcoin_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use core::fmt;

// Hardcoded hash length for SHA256 backed implementatoin.
const HASH_LENGTH_BYTES: usize = sha256::Hash::LEN;
// Output keying material max length multiple.
const MAX_OUTPUT_BYTES: usize = 255;

#[derive(Copy, Clone, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid number of blocks, too large output")
    }
}

impl std::error::Error for InvalidLength {}

/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
pub struct Hkdf {
    /// Pseudorandom key based on the extract step.
    prk: [u8; HASH_LENGTH_BYTES],
}

impl Hkdf {
    /// Initialize a HKDF by performing the extract step.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        // Hardcoding SHA256 for now, might be worth parameterizing hash function.
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(salt);
        hmac_engine.input(ikm);
        Self {
            prk: Hmac::from_engine(hmac_engine)
                .to_byte_array()
                .try_into()
                .expect("32 bytes hash"),
        }
    }

    /// Expand the key to generate an output.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        // Length of output keying material must be less than 255 * hash length.
        if okm.len() > (MAX_OUTPUT_BYTES * HASH_LENGTH_BYTES) {
            return Err(InvalidLength);
        }

        let mut counter = 1u8;
        // Ceiling calculation for the total number of hashes required for the expand.
        let total_hashes = (okm.len() + HASH_LENGTH_BYTES - 1) / HASH_LENGTH_BYTES;

        while counter <= total_hashes as u8 {
            let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.prk);

            // Handle special case for first hash where t is 0 byte,
            // otherwise include last hash in the HMAC input.
            if counter != 1u8 {
                let previous_start_index = (counter as usize - 2) * HASH_LENGTH_BYTES;
                let previous_end_index = (counter as usize - 1) * HASH_LENGTH_BYTES;
                hmac_engine.input(&okm[previous_start_index..previous_end_index]);
            }
            hmac_engine.input(info);
            hmac_engine.input(&[counter]);

            let t = Hmac::from_engine(hmac_engine);
            let start_index = (counter as usize - 1) * HASH_LENGTH_BYTES;
            // Handle special case of last hash not taking full hash length.
            let end_index = if counter == (total_hashes as u8) {
                okm.len()
            } else {
                counter as usize * HASH_LENGTH_BYTES
            };

            okm[start_index..end_index].copy_from_slice(&t.to_byte_array());

            counter = counter + 1;
        }

        Ok(())
    }
}
