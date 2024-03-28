use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, PacketHandler};
use bitcoin::p2p::Magic;
use bitcoin::{
    consensus::Decodable,
    p2p::{message::RawNetworkMessage, message_network::VersionMessage},
};
use core::fmt;
use hex::prelude::*;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;

const PROXY: &str = "127.0.0.1:1324";
const M: Magic = Magic::SIGNET;
type ChannelMessage = Result<(Vec<u8>, SendTo), PeerError>;

enum SendTo {
    Remote,
    Local,
}

enum PeerError {
    DecryptionFailure,
    BytesReadError,
    UnknownMessage,
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PeerError::DecryptionFailure => write!(f, "Decryption failed"),
            PeerError::BytesReadError => write!(f, "Error occurred while reading bytes"),
            PeerError::UnknownMessage => write!(f, "Received unknown message"),
        }
    }
}

async fn init_outbound_conn(mut sock: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initialing outbound connection.");
    let (mut proxy_reader, mut proxy_writer) = sock.split();
    let mut buf_reader = BufReader::new(&mut proxy_reader);
    let mut buffer = Vec::new();
    let n = buf_reader.read_to_end(&mut buffer).await?;
    println!("Bytes read from local connection: {n}");
    let recv_magic: [u8; 4] = buffer[..4].try_into()?;
    println!("Got magic: {}", recv_magic.to_lower_hex_string());
    if M.to_bytes().ne(&recv_magic) {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Invalid magic.",
        )));
    }
    println!("Matches our network.");
    let mut cursor = std::io::Cursor::new(buffer.clone());
    let msg = RawNetworkMessage::consensus_decode(&mut cursor)?;
    let command = msg.payload().command();
    println!("Message command: {}.", command.to_string());
    if !command.to_string().eq("version") {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Connections must open with Version message.",
        )));
    }
    let version = buffer.clone();
    let payload = buffer[24..].to_vec();
    let mut cursor = std::io::Cursor::new(payload);
    let ver = VersionMessage::consensus_decode_from_finite_reader(&mut cursor)?;
    let remote_addr = ver.receiver.socket_addr()?;
    println!("Reaching out to {}.", remote_addr.to_string());
    let mut outbound = TcpStream::connect(remote_addr).await?;
    let handshake = initialize_v2_handshake(None)?;
    println!("Initiating handshake.");
    outbound.write_all(&version).await?;
    println!("Sent handshake to remote.");
    let (mut remote_reader, mut remote_writer) = outbound.split();
    let mut buf_reader = BufReader::new(&mut remote_reader);
    let mut buffer = Vec::new();
    println!("Reading handshake response from remote.");
    let n = buf_reader.read_to_end(&mut buffer).await?;
    println!("Bytes read from remote host: {n}");
    println!("{}", &buffer.to_lower_hex_string());
    if n < 64 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Remote cannot perform V2 handshake. Disconnecting.",
        )));
    }
    // println!("Completing handshake.");
    // let finish_handshake = initiator_complete_v2_handshake(buffer, handshake, false)?;
    // remote_writer.write_all(&finish_handshake.message).await?;
    // println!("Remote handshake accepted. Sending garbage terminator.");
    // let mut packet_handler = finish_handshake.packet_handler;
    // println!("Session ID: {:?}", hex::encode(packet_handler.session_id));
    // println!("Their garbage terminator: {:?}", hex::encode(packet_handler.other_garbage_terminator));
    // let mut buffer = Vec::new();
    // remote_reader.read_to_end(&mut buffer).await?;
    // println!("Received: {:?}", hex::encode(buffer));
    Ok(())
    // let decrypt = packet_handler.clone();
    // let (tx, mut rx) = mpsc::channel::<ChannelMessage>(10);
    // let mut tx2 = tx.clone();
    // // then communicate as usual
    // tokio::spawn(async move {
    //     match communicate_outbound(tx, outbound, decrypt).await {
    //         Ok(()) => {
    //             println!("Remote disconnected.");
    //         }
    //         Err(_) => {
    //             println!("Error decrypting package from remote and writing to local.");
    //         }
    //     }
    // });
    // loop {
    //     while let Some(message) = rx.recv().await {
    //         match message {
    //             Ok((message, destination)) => match destination {
    //                 SendTo::Remote => {}
    //                 SendTo::Local => {
    //                     println!("Passing message to local node.");
    //                     proxy_writer.write_all(&message).await?;
    //                 }
    //             },
    //             Err(e) => {
    //                 return Err(Box::new(io::Error::new(io::ErrorKind::Other, "")));
    //             }
    //         }
    //     }
    // }
}

async fn communicate_outbound(
    channel: tokio::sync::mpsc::Sender<ChannelMessage>,
    mut remote: TcpStream,
    mut packet_handler: PacketHandler,
) -> Result<(), PeerError> {
    loop {
        let mut buffer = Vec::new();
        let n = remote
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| PeerError::BytesReadError)?;
        println!("Got a message from remote.");
        if n == 0 {
            println!("Remote node disconnected.");
            return Ok(());
        }
        println!("Decrypting messages.");
        let messages = packet_handler
            .receive_v2_packets(buffer, None)
            .map_err(|e| PeerError::DecryptionFailure)?;
        for message in messages {
            if let Some(message) = message.message {
                let mut cursor = std::io::Cursor::new(message.clone());
                let msg = RawNetworkMessage::consensus_decode(&mut cursor)
                    .map_err(|e| PeerError::UnknownMessage)?;
                let command = msg.payload().command();
                println!(
                    "Received a message from remote with command: {}.",
                    command.to_string()
                );
                channel
                    .send(Ok((message, SendTo::Local)))
                    .await
                    .map_err(|e| PeerError::BytesReadError)?;
            }
        }
    }
}

async fn communicate_local(
    channel: tokio::sync::mpsc::Sender<ChannelMessage>,
    mut local: TcpStream,
    mut packet_handler: PacketHandler,
) -> Result<(), PeerError> {
    loop {
        let mut buffer = Vec::new();
        let n = local
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| PeerError::BytesReadError)?;
        println!("Got a message from local.");
        if n == 0 {
            println!("Local node disconnected.");
            return Ok(());
        }
        let message = packet_handler
            .prepare_v2_packet(buffer, None, false)
            .map_err(|e| PeerError::BytesReadError)?;
        channel
            .send(Ok((message, SendTo::Remote)))
            .await
            .map_err(|e| PeerError::BytesReadError)?;
    }
}

#[tokio::main]
async fn main() {
    let proxy = TcpListener::bind(PROXY)
        .await
        .expect("Failed to bind to proxy port.");
    println!("Listening for connections on {PROXY}");
    loop {
        let (stream, _) = proxy
            .accept()
            .await
            .expect("Failed to accept inbound connection.");
        tokio::spawn(async move {
            match init_outbound_conn(stream).await {
                Ok(_) => {
                    println!("Ended connection with no errors.");
                }
                Err(e) => {
                    println!("Ended connection with error: {e}.");
                }
            };
        });
    }
}
