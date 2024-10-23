# v0.4.0

* Adds the `AsyncProtocol` high level interface for less boilerplate integration when using an async runtime (e.g. Tokio). Codes against the `futures-rs` traits, so any runtime which is compatible with those should be supported.
* Aync read functions should now be cancellation safe.
* The high level `Io` variant of the `ProtocolError` exposes if it is worth retrying with the V1 protocol with the new `ProtocolFailureSuggestion` type.
