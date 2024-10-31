# v0.5.0

* Replace the ownership-based interface of `AsyncProtocol` with mutable references which fit in the asynchronous ecosystem better.
* Add the `tokio` feature flag for easier asynchronous integration if caller is using the Tokio runtime.
* Fix a serialization bug in bitcoin network message.

# v0.4.0

* Adds the `AsyncProtocol` high level interface for less boilerplate integration when using an async runtime (e.g. Tokio). Codes against the `futures-rs` traits, so any runtime which is compatible with those should be supported.
* Aync read functions should now be cancellation safe.
* The high level `Io` variant of the `ProtocolError` exposes if it is worth retrying with the V1 protocol with the new `ProtocolFailureSuggestion` type.
