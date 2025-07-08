# BIP-324 Encrypted Transport Protocol

[BIP-324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) describes the V2 encrypted communication protocol for the bitcoin P2P network. 

## Motivation

Bitcoin's original P2P protocol, "V1", was designed without any encryption. Even though the data exchanged over the bitcoin P2P network is public to some degree, encrypted communications offers a number of benefits over plaintext communication. 

* Internet Service Providers (ISPs) can easily detect and censor plaintext bitcoin communication.  
* Plaintext message tampering, without detection, is trivial for a man in the middle (MitM) attacker. 
* Nefarious actors may associate metadata, such as IP addresses and transaction origins, without explicitly having to connect directly to peers.

BIP-324 - "V2" - encrypted communication protects against the above issues increasing the privacy and censorship-resistance of the bitcoin ecosystem. Any applications communicating with bitcoin nodes, including light clients, should make use of the V2 protocol.

## Packages

* `protocol` - Exports the `bip324` client library.
* `proxy` - A small side-car application to enable V2 communication for V1-only applications.
