# BIP-324 Traffic Shape Hiding

A traffic analysis resistance layer for BIP-324 encrypted bitcoin connections. Decoy packet and padding strategies are used to obscure communication patterns, attempting to make it harder for network observers to analyze bitcoin peer-to-peer communication patterns. The library follows a *sans I/O* design, but provides I/O drivers for easy entry points.

* **High-level I/O** - `io::ShapedProtocol` (sync) and `futures::ShapedProtocol` (async) handle the complete encrypted connection life-cycle with automatic traffic shaping, including handshake, padding, and decoy generation.
* **Lower-level components** - `TrafficShaper` manages the timing and generation of traffic obfuscation. It can be used directly if the caller wishes to drive the I/O themselves.

## Feature Flags

* `std` (default) - Standard library support with synchronous I/O.
* `tokio` - Asynchronous I/O support with `tokio` runtime.

## Minimum Supported Rust Version (MSRV)

This crate inherits the MSRV from the `bip324` protocol crate, which is **1.63.0**.

When using the `tokio` feature, the effective MSRV may be higher depending on the tokio version used.

## Traffic Shaping Strategies

The BIP-324 specification defines *decoy packets* as the primary mechanism for hiding the shape of encrypted traffic. Even with encryption, bitcoin p2p traffic patterns can be highly distinctive to a third party observer. Transactions and blocks have characteristic sizes, message exchanges follow predictable patterns (like initial handshake sequences, pings and pongs), and the timing between messages can reveal protocol state machines. Also, a new block propagates about every ten minutes. An observer monitoring encrypted traffic could potentially identify bitcoin nodes, track transaction propagation, or infer network topology.

This library uses decoy packets in two complementary ways, *packet padding* and *cover traffic*. Padding is where the library immediately follows a genuine packet send with a decoy packet. This makes it hard for observers to determine where one message ends and another begins, hiding the genuine packet size. Cover traffic is decoys continuously sent by a separate thread (or task) attempting to prevent traffic analysis based on communication patterns.

The goal is not to make bitcoin traffic completely unidentifiable, that maybe impossible, but rather to significantly increase the computational and analytical costs for observers. This creates a game of economic tradeoffs, how much bandwidth and processing power should nodes spend on decoy bytes versus how much effort observers must expend to identify bitcoin traffic? The ideal strategies would use minimal decoy bytes to impose maximum analysis costs on observers. Finding these efficient strategies remains an open research area, but even simple random noise raises the bar for passive network surveillance.

*No hard analysis has been done yet on the effectiveness of the following strategies to hide bitcoin p2p channel shape.*

### Padding Strategies

* `Disabled` - No padding, genuine packet sizes only (default).
* `Random` - Adds randomly sized decoy packet. Pure noise.
* *TODO* `Fixed` - Pad a message size to its nearest power of two. A mixnet strategy to make all messages look identical and avoid a randomness pattern which leaks information.

### Decoy Strategies

* `Disabled` - No automatic decoy packets, genuine writes only (default).
* `Random` - Sends randomly sized decoy packets at random intervals. Pure noise.
* *TODO* `Mimic` - Instead of hiding the bitcoin p2p traffic, embrace it but send even more bitcoin looking things.This could help break any sort of tracking analysis.
