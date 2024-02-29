use std::error::Error;

/// An error occured responding to an inbound handshake.
#[derive(Debug)]
pub enum ResponderHandshakeError {
    ECC(secp256k1::Error),
    /// The message was too short, too long, or was a V1 query.
    IncorrectMessage(String),
    EncryptionError(String),
}

impl std::fmt::Display for ResponderHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponderHandshakeError::ECC(e) => write!(f, "ECC error: {}", e),
            ResponderHandshakeError::IncorrectMessage(s) => write!(f, "Version error: {}", s),
            ResponderHandshakeError::EncryptionError(s) => write!(f, "Encryption error: {}", s),
        }
    }
}

impl Error for ResponderHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ResponderHandshakeError::ECC(e) => Some(e),
            ResponderHandshakeError::IncorrectMessage(_) => None,
            ResponderHandshakeError::EncryptionError(_e) => None,
        }
    }
}

/// The handshake could not be authenticated or completed properly.
#[derive(Debug)]
pub enum HandshakeCompletionError {
    MessageTooShort(String),
    TooMuchGarbage(String),
    NoTerminator(String),
    DecryptionError(String),
}

impl std::fmt::Display for HandshakeCompletionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeCompletionError::MessageTooShort(s) => write!(f, "Handshake error: {}", s),
            HandshakeCompletionError::TooMuchGarbage(s) => write!(f, "Handshake error: {}", s),
            HandshakeCompletionError::NoTerminator(s) => write!(f, "Handshake error: {}", s),
            HandshakeCompletionError::DecryptionError(s) => write!(f, "Handshake error: {}", s),
        }
    }
}

impl Error for HandshakeCompletionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeCompletionError::MessageTooShort(_s) => None,
            HandshakeCompletionError::TooMuchGarbage(_s) => None,
            HandshakeCompletionError::NoTerminator(_s) => None,
            HandshakeCompletionError::DecryptionError(_s) => None,
        }
    }
}

#[derive(Debug)]
pub enum FSChaChaError {
    StreamEncryption(String),
    StreamDecryption(String),
    Poly1305Encryption(String),
    Poly1305Decryption(String),
}

impl std::fmt::Display for FSChaChaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FSChaChaError::StreamEncryption(s) => write!(f, "Cipher error: {}", s),
            FSChaChaError::StreamDecryption(s) => write!(f, "Cipher error: {}", s),
            FSChaChaError::Poly1305Encryption(s) => write!(f, "Cipher error: {}", s),
            FSChaChaError::Poly1305Decryption(s) => write!(f, "Cipher error: {}", s),
        }
    }
}

impl Error for FSChaChaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FSChaChaError::StreamEncryption(_s) => None,
            FSChaChaError::StreamDecryption(_s) => None,
            FSChaChaError::Poly1305Encryption(_s) => None,
            FSChaChaError::Poly1305Decryption(_s) => None,
        }
    }
}
