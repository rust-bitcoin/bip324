use bip324::{initialize_v2_handshake, initiator_complete_v2_handshake};
use bitcoin::p2p::Magic;
use bitcoin::{
    consensus::Decodable,
    p2p::{
        message::{NetworkMessage::Version, RawNetworkMessage},
        message_network::VersionMessage,
    },
};
use hex;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const PROXY: &str = "127.0.0.1:1324";
const M: Magic = Magic::SIGNET;

async fn init_outbound_conn(mut sock: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initialing outbound connection.");
    let (mut proxy_reader, mut proxy_writer) = sock.split();
    let mut buf_reader = BufReader::new(&mut proxy_reader);
    let mut buffer = Vec::new();
    // only reads 4 bytes
    let n = buf_reader.read_to_end(&mut buffer).await?;
    println!("{n}");
    println!("{}", hex::encode(&buffer));
    let recv_magic: [u8; 4] = buffer[..4].try_into()?;
    println!("{}", hex::encode(recv_magic));
    println!("{}", hex::encode(M.to_bytes()));
    // not working
    if M.to_bytes().ne(&recv_magic) {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Invalid magic",
        )));
    }
    let mut cursor = std::io::Cursor::new(buffer);
    let decoding = VersionMessage::consensus_decode(&mut cursor)?;
    println!("Received a V1 version message.");
    println!("{:?}", decoding);
    let remote_addr = decoding.receiver.socket_addr()?;
    println!("Reaching out to {remote_addr}.");
    let mut outbound = TcpStream::connect(remote_addr).await?;
    let handshake = initialize_v2_handshake(None)?;
    println!("Initiating handshake.");
    outbound
        .write_all(handshake.message.clone().as_slice())
        .await?;
    let (mut remote_reader, mut remote_writer) = outbound.split();
    let mut buf_reader = BufReader::new(&mut remote_reader);
    let mut buffer = Vec::new();
    let n = buf_reader.read_to_end(&mut buffer).await?;
    println!("{n}");
    let finish_handshake = initiator_complete_v2_handshake(buffer, handshake)?;
    remote_writer.write_all(&finish_handshake.message).await?;
    let mut _packet_handler = finish_handshake.packet_handler;
    // then communicate as usual
    Ok(())
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
