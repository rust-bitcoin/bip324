// SPDX-License-Identifier: CC0-1.0

//! Benchmark exploring the performance impact of using a `BufReader` with BIP-324 protocol streams.
//!
//! The BIP-324 protocol requires many relatively small read operations. For every packet, first
//! the 3-byte length is read and then the rest of the packet. Bitcoin p2p messages are also
//! relatively small in size. These characteristics can lead to inefficient system calls.
//!
//! This example does not model real life very well, because the write half just dumps
//! all the messages at once. In reality, a bitcoin p2p connection is bursty or even
//! quite. And this doesn't model any sort of network latency or partially written
//! packets. But this example *does* highlight how during heavy write periods, a bufreader
//! improves performance by ironing out some of BIP-324 characteristics.
//!
//! # Usage
//!
//! ```bash
//! cargo run --release --example bufreader --features tokio
//! ```

use bip324::futures::Protocol;
use bip324::io::Payload;
use bip324::Role;
use std::fmt;
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};

/// Test scenario configuration.
#[derive(Clone)]
struct Scenario {
    name: &'static str,
    /// Message traffic pattern set by the sizes of messages to send.
    message_sizes: Vec<usize>,
    /// Number of times to repeat the message traffic pattern.
    iterations: usize,
}

impl Scenario {
    fn bitcoin_typical() -> Self {
        Self {
            name: "Bitcoin Traffic",
            // Some common bitcoin message sizes.
            //
            // * ping/pong: ~10 bytes
            // * inv: ~37 bytes per item
            // * addr: ~30 bytes per address
            // * tx: 200-500 bytes
            // * block header: ~80 bytes
            message_sizes: vec![10, 37, 30, 250, 80, 500, 37, 30, 10, 10],
            iterations: 10000,
        }
    }

    fn large_messages() -> Self {
        Self {
            name: "Large Messages",
            message_sizes: vec![8192, 16384, 65536],
            iterations: 1000,
        }
    }

    fn small_messages() -> Self {
        Self {
            name: "Small Messages",
            message_sizes: vec![1, 2, 3, 4, 5],
            iterations: 20000,
        }
    }

    fn total_messages(&self) -> usize {
        self.message_sizes.len() * self.iterations
    }

    fn total_bytes(&self) -> usize {
        self.message_sizes.iter().sum::<usize>() * self.iterations
    }

    /// Display benchmark results for this scenario.
    fn display_results(&self, without_buf: Duration, with_buf: Duration) {
        let improvement = ((without_buf.as_secs_f64() - with_buf.as_secs_f64())
            / without_buf.as_secs_f64())
            * 100.0;

        println!("{self}");
        println!("  Without BufReader: {} ms", without_buf.as_millis());
        println!("  With BufReader:    {} ms", with_buf.as_millis());
        println!("  Improvement:       {improvement:.1}%");
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} total messages, {} bytes",
            self.name,
            self.total_messages(),
            self.total_bytes()
        )
    }
}

/// Run benchmark for a specific scenario.
async fn benchmark_scenario(scenario: &Scenario) -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, _server_handle) = start_server(scenario.clone()).await?;

    let without_buf = Client::NonBuffered.run(&server_addr, scenario).await?;
    let with_buf = Client::Buffered.run(&server_addr, scenario).await?;

    scenario.display_results(without_buf, with_buf);

    Ok(())
}

/// Start the server which write out all the messages of a scenario.
async fn start_server(
    scenario: Scenario,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();

    let handle = tokio::spawn(async move {
        // Handle two connections per scenario, one with buffer and one without buffer.
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();

            let mut protocol = Protocol::new(
                p2p::Magic::BITCOIN,
                Role::Responder,
                None,
                None,
                reader,
                writer,
            )
            .await
            .unwrap();

            // Pre-allocate payloads to send.
            let payloads: Vec<Payload> = scenario
                .message_sizes
                .iter()
                .map(|&size| Payload::genuine(vec![0x42u8; size]))
                .collect();

            // Dump them all at once. This is not very realistic,
            // but the test is trying trying to measure the read
            // syscalls. Don't want to introduce write performance.
            for _ in 0..scenario.iterations {
                for payload in &payloads {
                    protocol.write(payload).await.unwrap();
                }
            }
        }
    });

    Ok((addr, handle))
}

/// Client reads all the messages.
enum Client {
    Buffered,
    NonBuffered,
}

impl Client {
    /// Run the client for a scenario and return the duration to read all the messages.
    async fn run(
        &self,
        server_addr: &str,
        scenario: &Scenario,
    ) -> Result<Duration, Box<dyn std::error::Error>> {
        let start = Instant::now();

        let stream = TcpStream::connect(server_addr).await?;
        let (reader, writer) = stream.into_split();

        match self {
            Client::Buffered => {
                let buffered_reader = BufReader::new(reader);
                let mut protocol = Protocol::new(
                    p2p::Magic::BITCOIN,
                    Role::Initiator,
                    None,
                    None,
                    buffered_reader,
                    writer,
                )
                .await?;

                // Read all messages
                for _ in 0..scenario.total_messages() {
                    let _payload = protocol.read().await?;
                }
            }
            Client::NonBuffered => {
                let mut protocol = Protocol::new(
                    p2p::Magic::BITCOIN,
                    Role::Initiator,
                    None,
                    None,
                    reader,
                    writer,
                )
                .await?;

                // Read all messages
                for _ in 0..scenario.total_messages() {
                    let _payload = protocol.read().await?;
                }
            }
        };

        Ok(start.elapsed())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenarios = vec![
        Scenario::bitcoin_typical(),
        Scenario::large_messages(),
        Scenario::small_messages(),
    ];

    for scenario in scenarios {
        benchmark_scenario(&scenario).await?;
    }

    Ok(())
}
