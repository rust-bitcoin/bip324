//! Blocking I/O traffic shaping wrapper for BIP-324 protocol.

use core::time::Duration;
use std::borrow::Borrow;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use bip324::io::{Payload, Protocol, ProtocolError, ProtocolReader, ProtocolWriter};
use bip324::Role;
use rand::Rng;

use crate::{
    AtomicTrafficStats, TrafficConfig, TrafficShaper, TrafficStats, DEFAULT_CHECK_INTERVAL_MS,
};

/// Shared writer state protected by a mutex.
struct WriterState<W, R = rand::rngs::StdRng> {
    writer: ProtocolWriter<W>,
    shaper: TrafficShaper<R>,
}

/// Traffic-shaped protocol reader half.
pub struct ShapedProtocolReader<R>
where
    R: Read,
{
    reader: ProtocolReader<R>,
    stats: Arc<AtomicTrafficStats>,
}

/// Traffic-shaped protocol writer half.
pub struct ShapedProtocolWriter<W>
where
    W: Write,
{
    writer_state: Arc<Mutex<WriterState<W>>>,
    stats: Arc<AtomicTrafficStats>,
    shutdown: Arc<AtomicBool>,
    decoy_handle: Option<thread::JoinHandle<()>>,
}

/// Traffic-shaped blocking protocol wrapper.
pub struct ShapedProtocol<R, W>
where
    R: Read,
    W: Write,
{
    reader: ShapedProtocolReader<R>,
    writer: ShapedProtocolWriter<W>,
}

impl<R, W> ShapedProtocol<R, W>
where
    R: Read,
    W: Write + Send + 'static,
{
    /// Create a new traffic-shaped BIP-324 protocol with automatic handshake.
    ///
    /// This function performs a complete BIP-324 handshake and sets up traffic shaping
    /// based on the provided configuration. Its interface matches that of the underlying
    /// [`bip324::io::Protocol`], but auto-applies traffic shaping decoy packets.
    ///
    /// # Arguments
    ///
    /// * `network` - The bitcoin network operating on.
    /// * `role` - Whether this peer is the `Initiator`or `Responder`.
    /// * `config` - Traffic shaping configuration specifying padding and decoy strategies.
    /// * `reader` - The readable half of the connection.
    /// * `writer` - The writable half of the connection.
    ///
    /// # Thread Safety
    ///
    /// The writer must be `Send + 'static` because it's moved into a background thread
    /// that handles automatic decoy packet generation. The reader only needs to implement
    /// `Read`.
    ///
    /// The background decoy thread will automatically shut down when the
    /// `ShapedProtocol` is dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::net::TcpStream;
    /// use bip324_traffic::{TrafficConfig, PaddingStrategy, DecoyStrategy};
    /// use bip324_traffic::io::ShapedProtocol;
    /// use bip324::Role;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = TcpStream::connect("127.0.0.1:8333")?;
    /// let reader = stream.try_clone()?;
    /// let writer = stream;
    ///
    /// let config = TrafficConfig::new()
    ///     .with_padding_strategy(PaddingStrategy::Random)
    ///     .with_decoy_strategy(DecoyStrategy::Random);
    ///
    /// let mut protocol = ShapedProtocol::new(
    ///     p2p::Magic::BITCOIN,
    ///     Role::Initiator,
    ///     config,
    ///     reader,
    ///     writer,
    /// ).map_err(|e| format!("Protocol error: {:?}", e))?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        magic: impl Borrow<[u8; 4]>,
        role: Role,
        config: TrafficConfig,
        reader: R,
        writer: W,
    ) -> Result<Self, ProtocolError> {
        let stats = Arc::new(AtomicTrafficStats::new());
        let mut shaper = TrafficShaper::new(config);
        let (garbage, decoys) = shaper.handshake(&stats);

        let protocol = Protocol::new(magic, role, garbage, decoys, reader, writer)?;
        let (protocol_reader, protocol_writer) = protocol.into_split();

        let writer_state = Arc::new(Mutex::new(WriterState {
            writer: protocol_writer,
            shaper,
        }));

        // Create shutdown flag and spawn decoy thread.
        let shutdown = Arc::new(AtomicBool::new(false));
        let writer_state_clone = writer_state.clone();
        let shutdown_clone = shutdown.clone();
        let stats_clone = stats.clone();
        let decoy_handle = thread::spawn(move || {
            decoy_thread(writer_state_clone, stats_clone, shutdown_clone);
        });

        Ok(Self {
            reader: ShapedProtocolReader {
                reader: protocol_reader,
                stats: stats.clone(),
            },
            writer: ShapedProtocolWriter {
                writer_state,
                shutdown,
                decoy_handle: Some(decoy_handle),
                stats,
            },
        })
    }
    /// Read a packet from the protocol.
    pub fn read(&mut self) -> Result<Payload, ProtocolError> {
        self.reader.read()
    }

    /// Write a payload with traffic shaping.
    pub fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        self.writer.write(payload)
    }

    /// Split the protocol into separate reader and writer halves.
    pub fn into_split(self) -> (ShapedProtocolReader<R>, ShapedProtocolWriter<W>) {
        (self.reader, self.writer)
    }
}

impl<R> ShapedProtocolReader<R>
where
    R: Read,
{
    /// Read a packet from the protocol.
    pub fn read(&mut self) -> Result<Payload, ProtocolError> {
        let payload = self.reader.read()?;
        self.stats.record_read(payload.contents().len());

        Ok(payload)
    }
}

impl<W> ShapedProtocolWriter<W>
where
    W: Write,
{
    /// Write a payload with traffic shaping.
    pub fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        let mut state = self.writer_state.lock().unwrap();
        if let Some(decoy) = state.shaper.pad(payload, &self.stats) {
            state.writer.write(&decoy)?;
        }
        state.writer.write(payload)?;

        Ok(())
    }
}

impl<W> Drop for ShapedProtocolWriter<W>
where
    W: Write,
{
    fn drop(&mut self) {
        // Signal the decoy thread to shutdown and wait for thread to exit.
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.decoy_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Decoy thread that periodically sends decoy packets.
fn decoy_thread<W, R>(
    writer_state: Arc<Mutex<WriterState<W, R>>>,
    stats: Arc<AtomicTrafficStats>,
    shutdown: Arc<AtomicBool>,
) where
    W: Write,
    R: Rng,
{
    let check_interval = Duration::from_millis(DEFAULT_CHECK_INTERVAL_MS);

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(check_interval);

        // Try to lock the writer state, skip if writing.
        let mut state = match writer_state.try_lock() {
            Ok(state) => state,
            Err(_) => continue,
        };

        if let Some(decoy) = state.shaper.decoy(&stats) {
            let _ = state.writer.write(&decoy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

    #[test]
    fn test_protocol_drop() {
        let reader = Cursor::new(Vec::new());
        let writer = Cursor::new(Vec::new());

        let config = TrafficConfig::new().with_decoy_strategy(crate::DecoyStrategy::Random);
        let result = ShapedProtocol::new(MAGIC, Role::Initiator, config, reader, writer);
        drop(result);
    }
}
