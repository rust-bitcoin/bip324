use secp256k1::{ellswift::ElligatorSwift, SecretKey};
use crate::PacketHandler;

#[derive(Debug)]
pub struct EcdhPoint {
    pub secret_key: SecretKey,
    pub elligator_swift: ElligatorSwift,
}

#[derive(Debug)]
pub struct InitiatorHandshake {
    pub message: Vec<u8>,
    pub point: EcdhPoint,
    pub(crate) garbage: Vec<u8>,
    
}

#[derive(Debug)]
pub struct ResponderHandshake {
    pub message: Vec<u8>,
    pub(crate) session_keys: SessionKeyMaterial,
    pub packet_handler: PacketHandler,
    pub(crate) initiator_garbage: Vec<u8>,
}

pub struct CompleteHandshake {
    pub message: Vec<u8>,
    pub(crate) session_keys: SessionKeyMaterial,
    pub packet_handler: PacketHandler
}

#[derive(Debug, Clone)]
pub struct SessionKeyMaterial {
    pub session_id: [u8; 32],
    pub initiator_length_key: [u8; 32],
    pub initiator_packet_key: [u8; 32],
    pub responder_length_key: [u8; 32],
    pub responder_packet_key: [u8; 32],
    pub initiator_garbage_terminator: [u8; 16],
    pub responder_garbage_terminator: [u8; 16],
}

#[derive(Debug)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

