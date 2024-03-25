use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, PacketHandler};
use bitcoin::p2p::Magic;
use bitcoin::{
    consensus::Decodable,
    p2p::{message::RawNetworkMessage, message_network::VersionMessage},
};
use core::fmt;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{broadcast, mpsc};

const PROXY: &str = "127.0.0.1:1324";
const M: Magic = Magic::SIGNET;
// type ChannelMessage = Result<(Vec<u8>, SendTo), PeerError>;

// #[derive(Clone, Copy, Debug)]
// enum SendTo {
//     Remote,
//     Local,
// }

// #[derive(Clone, Copy, Debug)]
// enum PeerError {
//     DecryptionFailure,
//     BytesReadError,
//     UnknownMessage,
// }

// impl fmt::Display for PeerError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match *self {
//             PeerError::DecryptionFailure => write!(f, "Decryption failed"),
//             PeerError::BytesReadError => write!(f, "Error occurred while reading bytes"),
//             PeerError::UnknownMessage => write!(f, "Received unknown message"),
//         }
//     }
// }

async fn init_outbound_conn(mut proxy: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initialing outbound connection.");
    let mut buffer: Vec<u8> = Vec::new();
    let n = proxy.read_to_end(&mut buffer).await?;
    println!("Bytes read from local connection: {n}");
    let recv_magic: [u8; 4] = buffer[..4].try_into()?;
    println!("Got magic: {}", hex::encode(recv_magic));
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
    println!("Connecting to: {}...", remote_addr.to_string());
    let mut outbound = TcpStream::connect(remote_addr).await?;
    println!("Sending Version message...");
    outbound
        .write_all(&version)
        .await?;
    println!("Sent version to remote.");
    let mut buffer = Vec::new();
    println!("Reading Version response from remote...");
    let n = outbound.read_to_end(&mut buffer).await?;
    println!("Bytes read from {} host: {n}", remote_addr.to_string());
    println!("{}", hex::encode(&buffer));
    if n < 64 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Remote closed connection. Disconnecting.",
        )));
    }
    println!("Writing the received message to local.");
    proxy.write_all(&buffer).await?;
    let mut cursor = std::io::Cursor::new(buffer.clone());
    let msg = RawNetworkMessage::consensus_decode(&mut cursor)?;
    let command = msg.payload().command();
    println!("Message command from {}: {}.", remote_addr.to_string(), command.to_string());
    let (mut client_reader, mut client_writer) = proxy.split();
    let (mut remote_reader, mut remote_writer) = outbound.split();
    loop {
        select! {
            res = tokio::io::copy(&mut client_reader, &mut remote_writer) => {
                match res {
                    Ok(bytes) => {
                        println!("Responded to {} with {bytes} bytes.", remote_addr.to_string());
                        if bytes == 0 {
                            return Err(Box::new(io::Error::new(
                                io::ErrorKind::Other,
                                "Client closed connection. Disconnecting.",
                            )));
                        }
                    },
                    Err(_) => {
                        return Err(Box::new(io::Error::new(
                            io::ErrorKind::Other,
                            "Remote closed connection: Disconnecting.",
                        )));
                    },
                }
            }, 
            res = tokio::io::copy(&mut remote_reader, &mut client_writer) => {
                match res {
                    Ok(bytes) => {
                        println!("Responded to local with {bytes} bytes.");
                        if bytes == 0 {
                            return Err(Box::new(io::Error::new(
                                io::ErrorKind::Other,
                                "Client closed connection. Disconnecting.",
                            )));
                        }
                    },
                    Err(_) => {
                        return Err(Box::new(io::Error::new(
                            io::ErrorKind::Other,
                            "Client closed connection. Disconnecting.",
                        )));
                    },
                }
            }, 
        }
     }
}

// async fn communicate_outbound(
//     sender: tokio::sync::mpsc::Sender<ChannelMessage>,
//     mut channel: tokio::sync::mpsc::Receiver<ChannelMessage>,
//     mut sock: TcpStream,
// ) -> Result<(), PeerError> {
//     loop {
//         let messages = channel.recv().await;
//         match messages {
//             Some(message) => {
//                 match message {
//                     Ok((message, _)) => {
//                         let mut cursor = std::io::Cursor::new(message.clone());
//                         let msg = RawNetworkMessage::consensus_decode(&mut cursor).map_err(|e| PeerError::UnknownMessage)?;
//                         let command = msg.payload().command();
//                         println!("Sending a message to remote. Command: {}.", command.to_string());
//                         sock.write_all(&message).await.map_err(|_e| PeerError::BytesReadError)?;
//                     },
//                     Err(_) => {
//                         return Err(PeerError::UnknownMessage)
//                     },
//                 }
//             },
//             None => {},
//         }
//         let mut buffer = Vec::new();
//         let mut cursor = std::io::Cursor::new(buffer.clone());
//         let n = sock.read_to_end(&mut buffer).await.map_err(|e| PeerError::BytesReadError)?;
//         if n > 0 {
//             let msg = RawNetworkMessage::consensus_decode(&mut cursor).map_err(|_e| PeerError::UnknownMessage)?;
//             let command = msg.payload().command();
//             println!("Message sent over channel to local thread: {}.", command.to_string());
//             sender.send(Ok((buffer, SendTo::Local))).await.map_err(|_e| PeerError::UnknownMessage)?;
//         }
//     }
// }

// async fn communicate_local(
//     sender: tokio::sync::mpsc::Sender<ChannelMessage>,
//     mut channel: tokio::sync::mpsc::Receiver<ChannelMessage>,
//     mut local: TcpStream,
// ) -> Result<(), PeerError> {
//     loop {
//         let messages = channel.recv().await;
//         match messages {
//             Some(message) => {
//                 match message {
//                     Ok((message, _)) => {
//                         let mut cursor = std::io::Cursor::new(message.clone());
//                         let msg = RawNetworkMessage::consensus_decode(&mut cursor).map_err(|e| PeerError::UnknownMessage)?;
//                         let command = msg.payload().command();
//                         println!("Sending a message to local. Command: {}.", command.to_string());
//                         local.write_all(&message).await.map_err(|_e| PeerError::BytesReadError)?;
//                     },
//                     Err(_) => {
//                         return Err(PeerError::UnknownMessage)
//                     },
//                 }
//             },
//             None => {},
//         }
//         let mut buffer = Vec::new();
//         let mut cursor = std::io::Cursor::new(buffer.clone());
//         let n = local.read_to_end(&mut buffer).await.map_err(|e| PeerError::BytesReadError)?;
//         if n > 0 {
//             let msg = RawNetworkMessage::consensus_decode(&mut cursor).map_err(|_e| PeerError::UnknownMessage)?;
//             let command = msg.payload().command();
//             println!("Message sent over channel: {}.", command.to_string());
//             sender.send(Ok((buffer, SendTo::Local))).await.map_err(|_e| PeerError::UnknownMessage)?;
//         }
//     }
// }

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