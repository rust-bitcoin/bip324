# BIP-324 Protocol

A BIP-324 library to establish and communicate over an encrypted channel.

The library is designed with a bare `no_std` and *Sans I/O* interface to keep it as agnostic as possible to application runtimes, but higher level interfaces are exposed for ease of use.

* **High-level I/O** - `io::Protocol` (sync) and `futures::Protocol` (async) handle the complete encrypted connection lifecycle including handshake, writes, and reads.
* **Low-level components** - For applications requiring more control, `Handshake` is a type-safe state machine for the handshake protocol and `CipherSession` manages encryption/decryption after the handshake.

## Feature Flags

* `std` - Standard library dependencies for I/O, memory allocation, and random number generators.
* `tokio` - High level I/O wrappers for the asynchronous tokio runtime.

## Minimum Supported Rust Version (MSRV)

This crate has a baseline MSRV of **1.63.0**.

However, the effective MSRV may be higher depending on the specific versions of dependencies selected by the caller. Currently, tokio is known to affect MSRV when using newer versions with the `tokio` feature flag, but other dependencies may also impact the effective MSRV in the future.
