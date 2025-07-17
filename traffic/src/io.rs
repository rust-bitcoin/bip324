//! Blocking I/O traffic shaping wrapper for BIP-324 protocol.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bip324::io::{Payload, Protocol, ProtocolError, ProtocolReader, ProtocolWriter};
use bip324::{Network, Role};
use rand::Rng;

use crate::{TrafficConfig, TrafficShaper, TrafficStats, DEFAULT_CHECK_INTERVAL_MS};

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
    stats: Arc<TrafficStats>,
}

/// Traffic-shaped protocol writer half.
pub struct ShapedProtocolWriter<W>
where
    W: Write,
{
    writer_state: Arc<Mutex<WriterState<W>>>,
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
    /// Create a new traffic-shaped protocol.
    pub fn new(
        network: Network,
        role: Role,
        config: TrafficConfig,
        reader: R,
        writer: W,
    ) -> Result<Self, ProtocolError> {
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::new(config, stats.clone());
        let (garbage, decoys) = shaper.handshake();

        let protocol = Protocol::new(network, role, garbage, decoys, reader, writer)?;
        let (protocol_reader, protocol_writer) = protocol.into_split();

        let writer_state = Arc::new(Mutex::new(WriterState {
            writer: protocol_writer,
            shaper,
        }));

        // Create shutdown flag and spawn decoy thread.
        let shutdown = Arc::new(AtomicBool::new(false));
        let writer_state_clone = writer_state.clone();
        let shutdown_clone = shutdown.clone();
        let decoy_handle = thread::spawn(move || {
            decoy_thread(writer_state_clone, shutdown_clone);
        });

        Ok(Self {
            reader: ShapedProtocolReader {
                reader: protocol_reader,
                stats,
            },
            writer: ShapedProtocolWriter {
                writer_state,
                shutdown,
                decoy_handle: Some(decoy_handle),
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
        if let Some(decoy) = state.shaper.pad(payload) {
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
fn decoy_thread<W, R>(writer_state: Arc<Mutex<WriterState<W, R>>>, shutdown: Arc<AtomicBool>)
where
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

        if let Some(decoy) = state.shaper.decoy() {
            let _ = state.writer.write(&decoy);
        }
    }
}
