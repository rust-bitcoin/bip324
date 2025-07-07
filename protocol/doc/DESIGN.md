# Design

Alice and Bob initiate a connection by sending three messages to each other to derive a number of shared secrets. Alice begins the connection by deriving a public/private keypair over `secp256k1`, the typical bitcoin curve. Alice is known as the *initiator*. She encodes the public key in the [Elligator Swift](https://eprint.iacr.org/2022/759.pdf) format (64-bytes), optionally pads it with some random garbage bytes, and sends the message to Bob. 

Bob, known as the *responder*, decodes the Elligator Swift public key, and derives an ephemeral public/private keypair himself. Using his public and private keys, as well as Alice's public key, Bob performs a variation of the Elliptic Curve Diffie Hellman algorithm to derive a shared key. From this shared key, Bob derives multiple keys and a session ID using the HKDF algorithm. Next, Bob creates garbage data, and sends his public key, garbage data, an encrypted packet using the garbage data, and a version negotiation to Alice.

With Bob's public key, Alice derives the shared secret and ensures the decrypted packet is authenticated with the garbage Bob sent her. Finally, Alice sends a "garbage terminator" and an encrypted packet using her garbage data, so Bob may authenticate she derived the correct secret and he can decode her messages. Alice and Bob may now freely exchange encrypted messages over the bitcoin V2 P2P protocol.

## ChaCha20Poly1305

BIP-324 elects to use the ChaCha20Poly1305 Authenticated Encryption with Addition Data (AEAD) algorithm under the hood. This is a combination of the ChaCha20 stream cipher and the Poly1305 message authentication code (MAC). In this context, "authentication" refers to the encrypted message's integrity, not to the identity of either party communicating.

Poly1305 is a purpose-built MAC, as opposed to something like an HMAC using SHA256 which leverages an existing hash scheme to build a message authentication code. Purpose-built introduces new complexity, but also allows for increased performance.
