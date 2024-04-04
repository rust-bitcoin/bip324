use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake, PacketHandler};
use core::fmt;
use hex::prelude::*;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;

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

/// Validate and bootstrap proxy connection.
async fn proxy_conn(mut client: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let remote_ip = bip324_proxy::peek_addr(&client).await?;

    println!("Reaching out to {}.", remote_ip);
    let mut outbound = TcpStream::connect(remote_ip).await?;

    // let handshake = initialize_v2_handshake(None)?;

    // println!("Initiating handshake.");
    // outbound.write_all(&version).await?;
    // println!("Sent handshake to remote.");
    // let (mut remote_reader, mut remote_writer) = outbound.split();
    // let mut buf_reader = BufReader::new(&mut remote_reader);
    // let mut buffer = Vec::new();
    // println!("Reading handshake response from remote.");
    // let n = buf_reader.read_to_end(&mut buffer).await?;
    // println!("Bytes read from remote host: {n}");
    // println!("{}", &buffer.to_lower_hex_string());
    // if n < 64 {
    //     return Err(Box::new(io::Error::new(
    //         io::ErrorKind::Other,
    //         "Remote cannot perform V2 handshake. Disconnecting.",
    //     )));
    // }

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

// async fn communicate_outbound(
//     channel: tokio::sync::mpsc::Sender<ChannelMessage>,
//     mut remote: TcpStream,
//     mut packet_handler: PacketHandler,
// ) -> Result<(), PeerError> {
//     loop {
//         let mut buffer = Vec::new();
//         let n = remote
//             .read_to_end(&mut buffer)
//             .await
//             .map_err(|e| PeerError::BytesReadError)?;
//         println!("Got a message from remote.");
//         if n == 0 {
//             println!("Remote node disconnected.");
//             return Ok(());
//         }
//         println!("Decrypting messages.");
//         let messages = packet_handler
//             .receive_v2_packets(buffer, None)
//             .map_err(|e| PeerError::DecryptionFailure)?;
//         for message in messages {
//             if let Some(message) = message.message {
//                 let mut cursor = std::io::Cursor::new(message.clone());
//                 let msg = RawNetworkMessage::consensus_decode(&mut cursor)
//                     .map_err(|e| PeerError::UnknownMessage)?;
//                 let command = msg.payload().command();
//                 println!(
//                     "Received a message from remote with command: {}.",
//                     command.to_string()
//                 );
//                 channel
//                     .send(Ok((message, SendTo::Local)))
//                     .await
//                     .map_err(|e| PeerError::BytesReadError)?;
//             }
//         }
//     }
// }

// async fn communicate_local(
//     channel: tokio::sync::mpsc::Sender<ChannelMessage>,
//     mut local: TcpStream,
//     mut packet_handler: PacketHandler,
// ) -> Result<(), PeerError> {
//     loop {
//         let mut buffer = Vec::new();
//         let n = local
//             .read_to_end(&mut buffer)
//             .await
//             .map_err(|e| PeerError::BytesReadError)?;
//         println!("Got a message from local.");
//         if n == 0 {
//             println!("Local node disconnected.");
//             return Ok(());
//         }
//         let message = packet_handler
//             .prepare_v2_packet(buffer, None, false)
//             .map_err(|e| PeerError::BytesReadError)?;
//         channel
//             .send(Ok((message, SendTo::Remote)))
//             .await
//             .map_err(|e| PeerError::BytesReadError)?;
//     }
// }

#[tokio::main]
async fn main() {
    let proxy = TcpListener::bind(bip324_proxy::DEFAULT_PROXY)
        .await
        .expect("Failed to bind to proxy port.");
    println!(
        "Listening for connections on {}",
        bip324_proxy::DEFAULT_PROXY
    );
    loop {
        let (stream, _) = proxy
            .accept()
            .await
            .expect("Failed to accept inbound connection.");
        // Spawn a new task per connection.
        tokio::spawn(async move {
            match proxy_conn(stream).await {
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
