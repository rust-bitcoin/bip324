//! # BIP-324 Traffic Shape Hiding
//!
//! Provides a traffic shape hiding layer over the BIP-324 library.
//!
//! This crate follows a sans-io design pattern where this module
//! handles traffic shaping decisions without performing any I/O operations.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bip324::io::Payload;
use rand::{Rng, SeedableRng};

#[cfg(feature = "tokio")]
pub mod futures;
pub mod io;

/// Maximum size for decoy packets.
const MAX_DECOY_SIZE_BYTES: usize = 1024;
const MAX_DECOY_INTERVAL_MS: u64 = 3000;
const DEFAULT_CHECK_INTERVAL_MS: u64 = 100;
const MAX_NUM_GARBAGE_BYTES: usize = 4095;

/// Padding strategies for genuine packets.
#[derive(Clone, Debug, Default)]
pub enum PaddingStrategy {
    /// No padding applied.
    #[default]
    Disabled,
    /// Random padding.
    Random,
}

/// Decoy packet generation strategies.
#[derive(Clone, Debug, Default)]
pub enum DecoyStrategy {
    /// No automatic decoys are sent.
    #[default]
    Disabled,
    /// Send decoys at random intervals with random sizes.
    Random,
}

/// Configuration for traffic shaping behavior.
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
    pub fn with_padding_strategy(mut self, strategy: PaddingStrategy) -> Self {
        self.padding_strategy = strategy;
        self
    }

    /// Set the decoy packet generation strategy.
    pub fn with_decoy_strategy(mut self, strategy: DecoyStrategy) -> Self {
        self.decoy_strategy = strategy;
        self
    }
}

/// Traffic statistics that can be updated atomically from multiple threads.
#[derive(Debug)]
struct TrafficStats {
    /// Total bytes read.
    bytes_read: AtomicU64,
    /// Total bytes written.
    bytes_written: AtomicU64,
    /// Number of messages read.
    messages_read: AtomicU64,
    /// Number of messages written.
    messages_written: AtomicU64,
    /// Last activity timestamp (milliseconds since epoch).
    last_activity_ms: AtomicU64,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            messages_read: AtomicU64::new(0),
            messages_written: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(0),
        }
    }

    /// Record bytes read.
    fn record_read(&self, bytes: usize) {
        self.bytes_read.fetch_add(bytes as u64, Ordering::Relaxed);
        self.messages_read.fetch_add(1, Ordering::Relaxed);
        self.update_last_activity();
    }

    /// Record bytes written.
    fn record_write(&self, bytes: usize) {
        self.bytes_written
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.messages_written.fetch_add(1, Ordering::Relaxed);
        self.update_last_activity();
    }

    fn update_last_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_activity_ms.store(now, Ordering::Relaxed);
    }

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
    config: TrafficConfig,
    stats: Arc<TrafficStats>,
    rng: R,
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
    /// Returns a tuple of (garbage_bytes, decoy_messages).
    ///
    /// * `garbage_bytes`: Random bytes to send as garbage (0-4095 bytes based on strategy).
    /// * `decoy_messages`: Vector of decoy payloads to send during handshake.
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

    /// Generate a decoy payload for padding for a genuine payload.
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
