//! Async traffic shaping wrapper for BIP-324 protocol.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use bip324::futures::{Protocol, ProtocolReader, ProtocolWriter};
use bip324::io::{Payload, ProtocolError, ProtocolFailureSuggestion};
use bip324::{Network, Role};

use crate::{TrafficConfig, TrafficShaper, TrafficStats, DEFAULT_CHECK_INTERVAL_MS};

/// Command sent to the writer task.
struct WriteCommand {
    /// Payload to write.
    payload: Payload,
    /// Channel to send the result back.
    result_tx: oneshot::Sender<Result<(), ProtocolError>>,
}

/// Traffic-shaped async protocol reader half.
pub struct ShapedProtocolReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    reader: ProtocolReader<R>,
    stats: Arc<TrafficStats>,
}

/// Traffic-shaped async protocol writer half.
pub struct ShapedProtocolWriter {
    write_tx: mpsc::UnboundedSender<WriteCommand>,
}

/// Traffic-shaped async protocol wrapper.
pub struct ShapedProtocol<R>
where
    R: AsyncRead + Unpin + Send,
{
    reader: ShapedProtocolReader<R>,
    writer: ShapedProtocolWriter,
}

impl<R> ShapedProtocol<R>
where
    R: AsyncRead + Unpin + Send,
{
    /// Create a new traffic-shaped BIP-324 protocol with automatic handshake.
    ///
    /// This function performs a complete BIP-324 handshake and sets up traffic shaping
    /// based on the provided configuration. Its interface matches that of the underlying
    /// [`bip324::futures::Protocol`], but auto-applies traffic shaping decoy packets.
    ///
    /// # Arguments
    ///
    /// * `network` - The bitcoin network operating on.
    /// * `role` - Whether this peer is the `Initiator`or `Responder`.
    /// * `config` - Traffic shaping configuration specifying padding and decoy strategies.
    /// * `reader` - The readable half of the connection.
    /// * `writer` - The writable half of the connection.
    ///
    /// # Async Runtime
    ///
    /// This function requires a tokio runtime and spawns a background task using
    /// `tokio::spawn`. The writer must be `Send + 'static` because it's moved into
    /// this background task.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tokio::net::TcpStream;
    /// use bip324_traffic::{TrafficConfig, PaddingStrategy, DecoyStrategy};
    /// use bip324_traffic::futures::ShapedProtocol;
    /// use bip324::{Network, Role};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> std::io::Result<()> {
    /// let stream = TcpStream::connect("127.0.0.1:8333").await?;
    /// let (reader, writer) = stream.into_split();
    ///
    /// let config = TrafficConfig::new()
    ///     .with_padding_strategy(PaddingStrategy::Random)
    ///     .with_decoy_strategy(DecoyStrategy::Random);
    ///
    /// let mut protocol = ShapedProtocol::new(
    ///     Network::Bitcoin,
    ///     Role::Initiator,
    ///     config,
    ///     reader,
    ///     writer,
    /// ).await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Cancellation Safety
    ///
    /// This function is *not* cancellation-safe.
    pub async fn new<W>(
        network: Network,
        role: Role,
        config: TrafficConfig,
        reader: R,
        writer: W,
    ) -> Result<Self, ProtocolError>
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let stats = Arc::new(TrafficStats::new());
        let mut shaper = TrafficShaper::new(config, stats.clone());
        let (garbage, decoys) = shaper.handshake();

        let protocol = Protocol::new(network, role, garbage, decoys, reader, writer).await?;
        let (protocol_reader, protocol_writer) = protocol.into_split();
        let (write_tx, write_rx) = mpsc::unbounded_channel();

        // Task will run as long as the write_tx isn't dropped.
        tokio::spawn(async move {
            writer_task(write_rx, protocol_writer, shaper).await;
        });

        Ok(Self {
            reader: ShapedProtocolReader {
                reader: protocol_reader,
                stats,
            },
            writer: ShapedProtocolWriter { write_tx },
        })
    }

    /// Read a packet from the protocol.
    pub async fn read(&mut self) -> Result<Payload, ProtocolError> {
        self.reader.read().await
    }

    /// Write a payload with traffic shaping.
    pub async fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        self.writer.write(payload).await
    }

    /// Split the protocol into separate reader and writer halves.
    pub fn into_split(self) -> (ShapedProtocolReader<R>, ShapedProtocolWriter) {
        (self.reader, self.writer)
    }
}

impl<R> ShapedProtocolReader<R>
where
    R: AsyncRead + Unpin + Send,
{
    /// Read a packet from the protocol.
    pub async fn read(&mut self) -> Result<Payload, ProtocolError> {
        let payload = self.reader.read().await?;
        self.stats.record_read(payload.contents().len());

        Ok(payload)
    }
}

impl ShapedProtocolWriter {
    /// Write a payload with traffic shaping.
    pub async fn write(&mut self, payload: &Payload) -> Result<(), ProtocolError> {
        let (result_tx, result_rx) = oneshot::channel();
        let cmd = WriteCommand {
            payload: payload.clone(),
            result_tx,
        };

        self.write_tx.send(cmd).map_err(|_| {
            ProtocolError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Writer task terminated unexpectedly",
                ),
                ProtocolFailureSuggestion::Abort,
            )
        })?;

        // Wait for result.
        result_rx.await.map_err(|_| {
            ProtocolError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Writer task dropped response channel",
                ),
                ProtocolFailureSuggestion::Abort,
            )
        })?
    }
}

/// Writer task that handles both genuine writes and decoy generation.
async fn writer_task<W>(
    mut write_rx: mpsc::UnboundedReceiver<WriteCommand>,
    mut writer: ProtocolWriter<W>,
    mut shaper: TrafficShaper,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut decoy_interval =
        tokio::time::interval(Duration::from_millis(DEFAULT_CHECK_INTERVAL_MS));

    loop {
        tokio::select! {
            // Handle write commands with padding.
            Some(cmd) = write_rx.recv() => {
                let mut result = Ok(());

                // First, send decoy packet if padding is enabled.
                if let Some(decoy) = shaper.pad(&cmd.payload) {
                    if let Err(e) = writer.write(&decoy).await {
                        result = Err(e);
                    }
                }

                // Then send the genuine packet if decoy succeeded (or there was no padding).
                if result.is_ok() {
                    if let Err(e) = writer.write(&cmd.payload).await {
                        result = Err(e);
                    }
                }

                // Send result back (ignore if receiver dropped).
                let _ = cmd.result_tx.send(result);
            }

            // Concurrently send decoys.
            _ = decoy_interval.tick() => {
                if let Some(decoy) = shaper.decoy() {
                    // Ignore write errors for decoys - they're best-effort.
                    let _ = writer.write(&decoy).await;
                }
            }

            // Exit if all write_tx senders dropped, don't send decoys forever.
            else => break,
        }
    }
}
