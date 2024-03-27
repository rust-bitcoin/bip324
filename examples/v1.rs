use bitcoin::consensus::Decodable;
use bitcoin::p2p::{Address, Magic};
use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

const PROXY: &str = "127.0.0.1:1324";
const M: Magic = Magic::SIGNET;

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
