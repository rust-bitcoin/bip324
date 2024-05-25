# V2 Proxy

A proxy process which allows V1-only clients to communicate over a V2 protocol. The process listens on port `1324` for V1 connections and requires the V1 client to send along the remote peer's IP address in the `addr_recv` field.

## Running the Proxy

`cargo run --bin proxy`

## Testing with Nakamoto

[Nakamoto](https://github.com/cloudhead/nakamoto) is a BIP-157/BIP-158 Light Client that communicates over the Bitcoin P2P network. With a single change, Nakamoto may be modified to use the proxy.

```diff
diff --git a/net/poll/src/reactor.rs b/net/poll/src/reactor.rs

--- a/net/poll/src/reactor.rs
+++ b/net/poll/src/reactor.rs
@@ -468,7 +468,7 @@ fn dial(addr: &net::SocketAddr) -> Result<net::TcpStream, io::Error> {
     sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
     sock.set_nonblocking(true)?;

-    match sock.connect(&(*addr).into()) {
+    match sock.connect(&net::SocketAddr::from(([127, 0, 0, 1], 1324)).into()) {
         Ok(()) => {}
         Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
         Err(e) if e.raw_os_error() == Some(libc::EALREADY) => {
```
