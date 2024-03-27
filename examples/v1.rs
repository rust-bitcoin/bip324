use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, PacketHandler};
use bitcoin::p2p::{Address, Magic};
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

async fn init_outbound_conn(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validating client connection.");
    // Peek the first 70 bytes, 24 for the header and 46 for the first part of the version message.
    let mut peek_bytes = [0; 70];
    let n = client.peek(&mut peek_bytes).await?;
    println!("Bytes read from local connection: {n}");
    println!("Got magic: {}", hex::encode(&peek_bytes[0..4]));
    if M.to_bytes().ne(&peek_bytes[0..4]) {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Invalid magic.",
        )));
    }

    let mut addr_bytes = &peek_bytes[44..];
    let remote_addr = Address::consensus_decode(&mut addr_bytes).expect("network address bytes");
    let remote_ip = remote_addr.socket_addr().expect("IP");
    println!("Initialing remote connection {}.", remote_ip);
    let mut remote = TcpStream::connect(remote_ip).await?;

    let (mut client_reader, mut client_writer) = client.split();
    let (mut remote_reader, mut remote_writer) = remote.split();
    loop {
        select! {
            res = tokio::io::copy(&mut client_reader, &mut remote_writer) => {
                match res {
                    Ok(bytes) => {
                        println!("Responded to {} with {bytes} bytes.", remote_ip);
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
