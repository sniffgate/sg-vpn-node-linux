
use tokio::{
    io, net::UdpSocket, sync::Mutex
};
use std::{net::SocketAddr, sync::Arc};
use tokio::task;

#[tokio::main]
async fn main() -> io::Result<()> {
    // The UDP socket for the WireGuard server
    let wireguard_server_addr = "127.0.0.1:51820";
    let wireguard_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // The UDP socket to receive forwarded traffic from the client
    let forwarding_server_addr = "0.0.0.0:80";
    let forwarding_socket = Arc::new(UdpSocket::bind(forwarding_server_addr).await?);

    println!("Server is running and listening on {}", forwarding_server_addr);

    let wireguard_socket_clone = Arc::clone(&wireguard_socket);
    let forwarding_socket_clone = Arc::clone(&forwarding_socket);

    let saved_client_addr = Arc::new(Mutex::new(SocketAddr::new("0.0.0.0".parse().unwrap(), 80)));
    let saved_client_addr_clone_1 = saved_client_addr.clone();
    let saved_client_addr_clone_2 = saved_client_addr.clone();

    // Task to handle forwarding from client to WireGuard server
    let forward_to_wireguard = task::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((len, client_addr)) = forwarding_socket.recv_from(&mut buf).await {
                println!("Received {} bytes from client at {}", len, client_addr);

                {
                    let mut sca = saved_client_addr_clone_1.lock().await;
                    *sca = client_addr;
                }

                if let Err(e) = wireguard_socket_clone.send_to(&buf[..len], wireguard_server_addr).await {
                    eprintln!("Failed to send to WireGuard server: {}", e);
                }
            }
        }
    });

    // Task to handle forwarding from WireGuard server to client
    let forward_to_client = task::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((response_len, _)) = wireguard_socket.recv_from(&mut buf).await {
                println!("Received {} bytes from WireGuard server", response_len);
                let client_addr: SocketAddr;
                
                {
                    client_addr = *saved_client_addr_clone_2.lock().await;
                }

                if let Err(e) = forwarding_socket_clone.send_to(&buf[..response_len], client_addr).await {
                    eprintln!("Failed to send to client: {}", e);
                }
            }
        }
    });

    // Wait for both tasks to complete (they won't unless there's an error)
    let _ = tokio::try_join!(forward_to_wireguard, forward_to_client);

    Ok(())
}
