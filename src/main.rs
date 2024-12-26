
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

                let deccrypted_data = ctr_encrypt(&buf[..len], b"32000000000000000000000000000000", b"1600000000000000");

                if let Err(e) = wireguard_socket_clone.send_to(&deccrypted_data, wireguard_server_addr).await {
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

                let encrypted_data = ctr_encrypt(&buf[..response_len], b"32000000000000000000000000000000", b"1600000000000000");

                if let Err(e) = forwarding_socket_clone.send_to(&encrypted_data, client_addr).await {
                    eprintln!("Failed to send to client: {}", e);
                }
            }
        }
    });

    // Wait for both tasks to complete (they won't unless there's an error)
    let _ = tokio::try_join!(forward_to_wireguard, forward_to_client);

    Ok(())
}









/// AES 256
// Libraries
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

// AES Encryption and Decryption
pub fn aes_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let key = aes::cipher::generic_array::GenericArray::from_slice(key);
    let cipher = aes::Aes256::new(key);

    let mut ciphertext = plaintext.to_vec();
    // Pad if necessary (simple PKCS#7 padding for demonstration)
    let padding_len = 16 - (ciphertext.len() % 16);
    for _ in 0..padding_len {
        ciphertext.push(padding_len as u8);
    }

    let mut blocks = ciphertext.chunks_exact_mut(16);
    for block in &mut blocks {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        cipher.encrypt_block(block);
    }
    ciphertext
}

pub fn aes_decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let key = aes::cipher::generic_array::GenericArray::from_slice(key);
    let cipher = aes::Aes256::new(key);

    let mut plaintext = ciphertext.to_vec();
    let mut blocks = plaintext.chunks_exact_mut(16);
    for block in &mut blocks {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        cipher.decrypt_block(block);
    }

    // Remove padding (PKCS#7)
    let padding_len = *plaintext.last().unwrap() as usize;
    plaintext.truncate(plaintext.len() - padding_len);
    plaintext
}



////// CTR mode
// Libraries
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
// use tokio::io::AsyncRead; // Import the CTR mode

type Aes256Ctr = Ctr128BE<Aes256>; // Define the Aes256Ctr type

// AES-CTR Encryption and Decryption
pub fn ctr_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let key = aes::cipher::generic_array::GenericArray::from_slice(key);
    let iv = aes::cipher::generic_array::GenericArray::from_slice(iv);
    let mut cipher = Aes256Ctr::new(key, iv);

    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    ciphertext
}

pub fn ctr_decrypt(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    // Decryption is the same as encryption in CTR mode
    ctr_encrypt(ciphertext, key, iv)
}
