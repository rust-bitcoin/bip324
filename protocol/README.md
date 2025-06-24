# Protocol

A BIP324 library to establish and communicate over an encrypted channel.

The library is designed with a bare `no_std` and "Sans I/O" interface to keep it as agnostic as possible to application runtimes, but higher level interfaces are exposed for ease of use.

The `futures` feature includes the high-level `AsyncProcotol` type which helps create and manage an encrypted channel. 

The lower-level `CipherSession` and `Handshake` types can be directly used by applications which require more control. The handshake performs the one-and-a-half round trip dance between the peers in order to generate secret materials and verify a channel. A successful handshake results in a cipher session which performs the encrypt and decrypt operations for the lifetime of the channel.

## Feature Flags

* `std` -- Standard library dependencies for I/O, memory allocation, and random number generators.
* `futures` -- High level wrappers for asynchronous read and write runtimes using agnostic futures-rs traits.
* `tokio` -- Same wrappers as `futures`, but using the popular tokio runtime's specific traits instead of futures-rs.

## Minimum Supported Rust Version (MSRV)

This crate has a baseline MSRV of **1.63.0**.

However, the effective MSRV may be higher depending on the specific versions of dependencies selected by the caller. Currently, tokio is known to affect MSRV when using newer versions with the `tokio` feature flag, but other dependencies may also impact the effective MSRV in the future.
