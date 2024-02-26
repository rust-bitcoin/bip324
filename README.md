## BIP324 Rust Implementation

#### Introduction

[BIP 324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) describes an encrypted communication protocol over the Bitcoin P2P network. Encrypted messages offer a number of benefits over plaintext communcation, even though the data exchanged over the Bitcoin P2P network is public to some degree. For instance, plaintext message tampering without detection is trivial for a man in the middle (MitM) attacker. A nefarious actor may associate metadata such as IP addresses and transaction origins without explicitly having to connect directly to peers. BIP 324 - "V2" - transport forces nefarious observers to actively connect to peers as opposed to passively observing network traffic. Furthermore, V2 messages over TCP/IP look no different than random noise, making censorship impractical from an Internet Service Provider level.

#### License

BSD 3-Clause

#### Protocol Brief

Alice and Bob initiate a connection by sending three messages to each other to derive a number of shared secrets. Alice begins the connection by deriving a public/private keypair over `secp256k1`, the typical Bitcoin curve. Alice is known as the initiator here, She encodes the public key in the Elligator Swift format (64-bytes), optionally pads it with some random garbage bytes, and sends the message to Bob. Bob, known as the responder, decodes the Elligator Swift public key, and derives an ephemeral public/private keypair himself. Using his public and private keys, as well as Alice's public key, Bob performs a variation of the Elliptic Curve Diffie Hellman algorithm to derive a shared key. From this shared key, Bob derives multiple keys and a session ID using the HKDF algorithm. Using his keys, Bob creates garbage data, and sends his public key, garbage, encrypted packet using the garbage, and a version negotiation to Alice. With Bob's public key, Alice derives the shared secret and ensures the decrypted packet is authenticated with the garbage Bob sent her. Finally, Alice sends a "garbage terminator" and an encrypted packet using her garbage data, so Bob may authenticate she derived the correct secret and he can decode her messages. Alice and Bob may now freely exchange encrypted messages.

#### Implementation

The crate exposes 4 functions, of which each party need to call only two for a complete handshake. For encrypting and decrypting messages, a `PacketHandler` struct is exposed with two methods. All messages are expected to be a `Vec<u8>` arrays of bytes, works well with `TcpStream` from the standard library and Bitcoin P2P messages. To initiate a handshake Alice calls `initialize_v2_handshake` and `initiator_complete_v2_handshake`. Similarly, to respond to a V2 handshake, Bob calls `receive_v2_handshake` and `responder_complete_v2_handshake`. Each function creates the appropriate message as well as additional data to complete the handshake. Notice Bob declares his handshake as `mut` in order to complete it. Errors thrown by each of these functions should result in disconnection from the peer.

```rust
use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, receive_v2_handshake, responder_complete_v2_handshake};

fn main() {
    // Alice starts a connection with Bob by making a pub/priv keypair and sending a message to Bob.
    let handshake_init = initialize_v2_handshake(None).unwrap();
    // Bob parses Alice's message, generates his pub/priv key, and sends a message back.
    let mut bob_handshake = receive_v2_handshake(handshake_init.message.clone()).unwrap();
    // Alice finishes her handshake by using her keys from earlier, and sending a final message to Bob.
    let alice_handshake = initiator_complete_v2_handshake(bob_handshake.message.clone(), handshake_init).unwrap();
    // Bob checks Alice derived the correct keys for the session by authenticating her first message.
    responder_complete_v2_handshake(alice_handshake.message.clone(), &mut handshake_response).unwrap();
    // Alice and Bob can freely exchange encrypted messages using the packet handler returned by each handshake.
    let mut alice = alice_handshake.packet_handler;
    let mut bob = bob_handshake.packet_handler;
    let message = b"Hello world".to_vec();
    let encrypted_message_to_alice = bob.prepare_v2_packet(message.clone(), None, false).unwrap();
    let secret_message = alice.receive_v2_packet(encrypted_message_to_alice, None).unwrap();
    assert_eq!(message, secret_message);
    let message = b"Goodbyte!".to_vec();
    let encrypted_message_to_bob = alice.prepare_v2_packet(message.clone(), None, false).unwrap();
    let secret_message = bob.receive_v2_packet(encrypted_message_to_bob, None).unwrap();
    assert_eq!(message, secret_message);
}
```

#### Coverage

The implementation is tested against vectors from the BIP 324 reference and a number of additional library tests.


