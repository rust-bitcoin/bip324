use bitcoin_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use core::fmt;

/// Structure for InvalidLength, used for output error handling.
#[derive(Copy, Clone, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid number of blocks, too large output")
    }
}

// Hardcoding to SHA256 hash and hmac implemenation.
pub struct Hkdf {
    prk: Hmac<sha256::Hash>,
}

impl Hkdf {
    // TODO: make salt optional.
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(salt);
        hmac_engine.input(ikm);
        Hkdf {
            prk: Hmac::from_engine(hmac_engine),
        }
    }
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        // TODO: actually loop and do not assume exact 32 byte match.
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.prk.to_byte_array());
        hmac_engine.input(info);
        hmac_engine.input(&[1u8]);
        let t = Hmac::from_engine(hmac_engine);
        okm.copy_from_slice(&t.to_byte_array());
        return Ok(());
    }
}
