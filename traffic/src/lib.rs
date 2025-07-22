//! # BIP-324 Traffic Shape Hiding
//!
//! Provides a traffic shape hiding layer over the BIP-324 encrypted peer-to-peer protocol library.
//!
//! ## Security Considerations
//!
//! * **Message size analysis**: Padding makes it harder to identify message types by size.
//! * **Timing analysis**: Decoy packets obscure genuine communication patterns.
//!
//! ## Examples
//!
//! This crate follows a sans-io design pattern where this module handles traffic shaping
//! decisions without performing any I/O operations. The core logic is I/O-agnostic, with
//! separate modules providing synchronous (`io`) and asynchronous (`futures`) wrappers.
//!
//! ### Synchronous I/O Usage
//!
//! ```no_run
//! use std::net::TcpStream;
//! use bip324_traffic::{TrafficConfig, PaddingStrategy, DecoyStrategy};
//! use bip324_traffic::io::ShapedProtocol;
//! use bip324::{Network, Role};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TrafficConfig::new()
//!     .with_padding_strategy(PaddingStrategy::Random)
//!     .with_decoy_strategy(DecoyStrategy::Random);
//!
//! let stream = TcpStream::connect("127.0.0.1:8333")?;
//! let reader = stream.try_clone()?;
//! let writer = stream;
//!
//! let mut protocol = ShapedProtocol::new(
//!     Network::Bitcoin,
//!     Role::Initiator,
//!     config,
//!     reader,
//!     writer,
//! ).map_err(|e| format!("Protocol error: {:?}", e))?;
//!
//! use bip324::io::Payload;
//! let message = Payload::genuine(b"Hello, bitcoin!".to_vec());
//! protocol.write(&message).map_err(|e| format!("Write error: {:?}", e))?;
//!
//! let received = protocol.read().map_err(|e| format!("Read error: {:?}", e))?;
//! println!("Received: {:?}", received.contents());
//! # Ok(())
//! # }
//! ```
//!
//! ### Asynchronous I/O Usage (with Tokio)
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # fn test() {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use bip324_traffic::{TrafficConfig, PaddingStrategy, DecoyStrategy};
//! use bip324_traffic::futures::ShapedProtocol;
//! use bip324::{Network, Role};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (local, remote) = tokio::io::duplex(1024);
//! # let (reader, writer) = tokio::io::split(local);
//! let config = TrafficConfig::new()
//!     .with_padding_strategy(PaddingStrategy::Random)
//!     .with_decoy_strategy(DecoyStrategy::Random);
//!
//! let mut protocol = ShapedProtocol::new(
//!     Network::Bitcoin,
//!     Role::Initiator,
//!     config,
//!     reader,
//!     writer,
//! ).await.map_err(|e| format!("Protocol error: {:?}", e))?;
//!
//! use bip324::io::Payload;
//! let message = Payload::genuine(b"Hello, async bitcoin!".to_vec());
//! protocol.write(&message).await.map_err(|e| format!("Write error: {:?}", e))?;
//!
//! let received = protocol.read().await.map_err(|e| format!("Read error: {:?}", e))?;
//! println!("Received: {:?}", received.contents());
//! # Ok(())
//! # }
//! # }
//! ```

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bip324::io::Payload;
use rand::{Rng, SeedableRng};

#[cfg(feature = "tokio")]
pub mod futures;
pub mod io;

/// Maximum size for decoy packets in bytes.
const MAX_DECOY_SIZE_BYTES: usize = 1024;
/// Maximum interval between automatic decoy packets in milliseconds.
const MAX_DECOY_INTERVAL_MS: u64 = 3000;
/// Default interval for checking whether to send decoy packets.
const DEFAULT_CHECK_INTERVAL_MS: u64 = 100;
/// Maximum number of garbage bytes that can be sent during handshake per BIP-324 spec.
const MAX_NUM_GARBAGE_BYTES: usize = 4095;

/// Padding strategies for genuine packets.
///
/// Padding adds extra data to genuine messages to obscure their true size,
/// making it harder for an observer to infer message types based on size patterns.
#[derive(Clone, Debug, Default)]
pub enum PaddingStrategy {
    /// No padding applied.
    ///
    /// Messages are sent at their original size. This offers no protection
    /// against traffic analysis based on message size patterns.
    #[default]
    Disabled,
    /// Random padding.
    ///
    /// Adds a random amount of padding data to messages, the noise
    /// might make it more difficult to determine the original message
    /// types from network traffic.
    Random,
}

/// Decoy packet generation strategies.
///
/// Decoy packets are dummy messages that contain no meaningful data but help
/// obscure real communication patterns from network observers.
#[derive(Clone, Debug, Default)]
pub enum DecoyStrategy {
    /// No automatic decoys are sent.
    ///
    /// Only genuine messages are transmitted. This provides no protection
    /// against timing analysis attacks.
    #[default]
    Disabled,
    /// Send decoys at random intervals with random sizes.
    ///
    /// Decoy packets are sent at random intervals (0-3000ms) with random
    /// sizes (1-1024 bytes) to mask to add noise across genuine communication
    /// patterns.
    Random,
}

/// Configuration for traffic shaping behavior.
///
/// # Example
///
/// ```no_run
/// use bip324_traffic::{TrafficConfig, PaddingStrategy, DecoyStrategy};
///
/// let config = TrafficConfig::new()
///     .with_padding_strategy(PaddingStrategy::Random)
///     .with_decoy_strategy(DecoyStrategy::Random);
/// ```
#[derive(Clone, Debug, Default)]
pub struct TrafficConfig {
    /// Padding strategy for genuine packets.
    padding_strategy: PaddingStrategy,
    /// Decoy packet generation strategy.
    decoy_strategy: DecoyStrategy,
}

impl TrafficConfig {
    /// Create a new traffic configuration with all features disabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the padding strategy for genuine packets.
    ///
    /// # Arguments
    ///
    /// * `strategy` - The padding strategy to use for genuine messages
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bip324_traffic::{TrafficConfig, PaddingStrategy};
    ///
    /// let config = TrafficConfig::new()
    ///     .with_padding_strategy(PaddingStrategy::Random);
    /// ```
    pub fn with_padding_strategy(mut self, strategy: PaddingStrategy) -> Self {
        self.padding_strategy = strategy;
        self
    }

    /// Set the decoy packet generation strategy.
    ///
    /// # Arguments
    ///
    /// * `strategy` - The strategy to use for generating decoy packets
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bip324_traffic::{TrafficConfig, DecoyStrategy};
    ///
    /// let config = TrafficConfig::new()
    ///     .with_decoy_strategy(DecoyStrategy::Random);
    /// ```
    pub fn with_decoy_strategy(mut self, strategy: DecoyStrategy) -> Self {
        self.decoy_strategy = strategy;
        self
    }
}

/// Traffic statistics that can be updated atomically from multiple threads.
///
/// # Thread Safety
///
/// All methods on this struct are safe to call from multiple threads concurrently.
/// The statistics use atomic operations to ensure consistency without locks.
#[derive(Debug)]
struct TrafficStats {
    /// Total bytes read from the connection.
    bytes_read: AtomicU64,
    /// Total bytes written to the connection.
    bytes_written: AtomicU64,
    /// Number of messages read from the connection.
    messages_read: AtomicU64,
    /// Number of messages written to the connection.
    messages_written: AtomicU64,
    /// Last activity timestamp (milliseconds since epoch).
    last_activity_ms: AtomicU64,
}

impl TrafficStats {
    /// Create a new traffic statistics tracker with all counters at zero.
    fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            messages_read: AtomicU64::new(0),
            messages_written: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Record bytes read from the connection.
    fn record_read(&self, bytes: usize) {
        self.bytes_read.fetch_add(bytes as u64, Ordering::Relaxed);
        self.messages_read.fetch_add(1, Ordering::Relaxed);
        self.update_last_activity();
    }

    /// Record bytes written to the connection.
    fn record_write(&self, bytes: usize) {
        self.bytes_written
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.messages_written.fetch_add(1, Ordering::Relaxed);
        self.update_last_activity();
    }

    /// Update the last activity timestamp to the current time.
    fn update_last_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_activity_ms.store(now, Ordering::Relaxed);
    }

    /// Calculate milliseconds elapsed since the last recorded activity.
    ///
    /// # Returns
    ///
    /// * `0` if no activity has been recorded yet.
    fn ms_since_last_activity(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let last = self.last_activity_ms.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

/// Traffic shaper that manages decoy packet generation.
struct TrafficShaper<R = rand::rngs::StdRng> {
    /// Configuration for traffic shaping behavior.
    config: TrafficConfig,
    /// Statistics tracker for monitoring traffic.
    stats: Arc<TrafficStats>,
    /// Random number generator for generating random data and intervals.
    rng: R,
    /// Cached quiet time in milliseconds for the next decoy packet.
    quiet_time_ms: Option<u64>,
}

impl TrafficShaper {
    /// Create a new traffic shaper with the given configuration and default RNG.
    fn new(config: TrafficConfig, stats: Arc<TrafficStats>) -> Self {
        Self::with_rng(config, stats, rand::rngs::StdRng::from_entropy())
    }
}

impl<R: Rng> TrafficShaper<R> {
    /// Create a new traffic shaper with the given configuration and custom RNG.
    fn with_rng(config: TrafficConfig, stats: Arc<TrafficStats>, rng: R) -> Self {
        Self {
            config,
            stats,
            rng,
            quiet_time_ms: None,
        }
    }

    /// Generate garbage bytes and decoy messages for the BIP-324 handshake.
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(garbage_bytes, decoy_messages)`:
    ///
    /// * `garbage_bytes` - Optional vector of random bytes to send as garbage
    /// * `decoy_messages` - Optional vector of decoy message contents
    pub fn handshake(&mut self) -> (Option<Vec<u8>>, Option<Vec<Vec<u8>>>) {
        let garbage = match self.config.padding_strategy {
            PaddingStrategy::Disabled => None,
            PaddingStrategy::Random => {
                let size = self.rng.gen_range(0..=MAX_NUM_GARBAGE_BYTES);
                let mut garbage = vec![0u8; size];
                self.rng.fill_bytes(&mut garbage);
                Some(garbage)
            }
        };

        let decoys = match self.config.decoy_strategy {
            DecoyStrategy::Disabled => None,
            DecoyStrategy::Random => {
                let num_decoys = self.rng.gen_range(0..=3);
                let mut decoys = Vec::with_capacity(num_decoys);

                for _ in 0..num_decoys {
                    let size = self.rng.gen_range(1..=MAX_DECOY_SIZE_BYTES);
                    let mut contents = vec![0u8; size];
                    self.rng.fill_bytes(&mut contents);
                    self.stats.record_write(contents.len());
                    decoys.push(contents);
                }

                Some(decoys)
            }
        };

        (garbage, decoys)
    }

    /// Generate a decoy payload based on traffic patterns.
    ///
    /// # Returns
    ///
    /// * `Some(Payload)` - A decoy payload if it's time to send one based on strategy.
    /// * `None` - If decoys are disabled or it's not time to send one based on strategy.
    ///
    /// # Stats
    ///
    /// This method records statistics for both the genuine payload and the
    /// generated decoy to maintain accurate traffic metrics.
    fn decoy(&mut self) -> Option<Payload> {
        match &mut self.config.decoy_strategy {
            DecoyStrategy::Disabled => None,
            DecoyStrategy::Random => {
                let quite_time_ms = self.quiet_time_ms.unwrap_or_else(|| {
                    let quiet_time = self.rng.gen_range(1..=MAX_DECOY_INTERVAL_MS);
                    self.quiet_time_ms = Some(quiet_time);
                    quiet_time
                });

                if self.stats.ms_since_last_activity() < quite_time_ms {
                    return None;
                }

                self.quiet_time_ms = None;
                let decoy = Payload::decoy(vec![0; self.rng.gen_range(1..=MAX_DECOY_SIZE_BYTES)]);
                self.stats.record_write(decoy.contents().len());
                Some(decoy)
            }
        }
    }

    /// Generate a decoy payload for padding a genuine payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The genuine payload being sent.
    ///
    /// # Returns
    ///
    /// * `Some(Payload)` - A decoy payload to send with the genuine message.
    /// * `None` - If padding is disabled.
    ///
    /// # Stats
    ///
    /// This method records statistics for both the genuine payload and the
    /// generated decoy to maintain accurate traffic metrics.
    fn pad(&mut self, payload: &Payload) -> Option<Payload> {
        match &mut self.config.padding_strategy {
            PaddingStrategy::Disabled => None,
            PaddingStrategy::Random => {
                let decoy = Payload::decoy(vec![0; self.rng.gen_range(1..=MAX_DECOY_SIZE_BYTES)]);
                self.stats.record_write(payload.contents().len());
                self.stats.record_write(decoy.contents().len());
                Some(decoy)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;

    #[test]
    fn test_traffic_config_builder() {
        let config = TrafficConfig::new();
        assert!(matches!(config.padding_strategy, PaddingStrategy::Disabled));
        assert!(matches!(config.decoy_strategy, DecoyStrategy::Disabled));

        let config = TrafficConfig::new()
            .with_padding_strategy(PaddingStrategy::Random)
            .with_decoy_strategy(DecoyStrategy::Random);
        assert!(matches!(config.padding_strategy, PaddingStrategy::Random));
        assert!(matches!(config.decoy_strategy, DecoyStrategy::Random));
    }

    #[test]
    fn test_traffic_stats_recording() {
        let stats = TrafficStats::new();

        assert_eq!(stats.bytes_read.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_written.load(Ordering::Relaxed), 0);
        assert_eq!(stats.messages_read.load(Ordering::Relaxed), 0);
        assert_eq!(stats.messages_written.load(Ordering::Relaxed), 0);

        stats.record_read(100);
        assert_eq!(stats.bytes_read.load(Ordering::Relaxed), 100);
        assert_eq!(stats.messages_read.load(Ordering::Relaxed), 1);

        stats.record_write(50);
        assert_eq!(stats.bytes_written.load(Ordering::Relaxed), 50);
        assert_eq!(stats.messages_written.load(Ordering::Relaxed), 1);

        assert!(stats.ms_since_last_activity() < 100);
    }

    #[test]
    fn test_traffic_shaper_handshake_disabled() {
        let config = TrafficConfig::new();
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::with_rng(config, stats, StepRng::new(0, 1));

        let (garbage, decoys) = shaper.handshake();
        assert!(garbage.is_none());
        assert!(decoys.is_none());
    }

    #[test]
    fn test_traffic_shaper_handshake_with_padding() {
        let config = TrafficConfig::new().with_padding_strategy(PaddingStrategy::Random);
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::with_rng(config, stats, StepRng::new(1, 1));

        let (garbage, decoys) = shaper.handshake();
        assert!(garbage.is_some());
        assert!(decoys.is_none());

        let garbage = garbage.unwrap();
        assert!(garbage.len() <= MAX_NUM_GARBAGE_BYTES);
    }

    #[test]
    fn test_traffic_shaper_handshake_with_decoys() {
        let config = TrafficConfig::new().with_decoy_strategy(DecoyStrategy::Random);
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::with_rng(config, stats.clone(), StepRng::new(1, 1));

        let (garbage, decoys) = shaper.handshake();
        assert!(garbage.is_none());
        assert!(decoys.is_some());
    }

    #[test]
    fn test_traffic_shaper_padding_disabled() {
        let config = TrafficConfig::new(); // Padding disabled by default
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::with_rng(config, stats, StepRng::new(0, 1));

        let genuine = Payload::genuine(vec![1, 2, 3]);
        let padding = shaper.pad(&genuine);

        assert!(padding.is_none());
    }
}
