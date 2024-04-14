# Proxy

A proxy process which allows V1-only clients to communicate over a V2 protocol. The process listens on port `1324` for V1 connections and requires the V1 client to send along the remote peer's IP address in the `addr_recv` field.
