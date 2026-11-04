use fips_core::{Config, FipsEndpoint, FipsEndpointMessage};
#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("config path");
    let nsec = std::env::args().nth(2).expect("nsec hex");
    let config = Config::load_file(std::path::Path::new(&path)).expect("config");
    let ep = FipsEndpoint::builder()
        .config(config)
        .identity_nsec(nsec)
        .without_system_tun()
        .bind()
        .await
        .expect("bind");
    let ep = std::sync::Arc::new(ep);
    println!("npub {}", ep.npub());
    // optional: act as the session initiator towards <target_npub>, sending ICMP echo requests src_ip -> dst_ip
    if let (Some(target), Some(src), Some(dst)) = (std::env::args().nth(3), std::env::args().nth(4), std::env::args().nth(5)) {
        let id = fips_core::PeerIdentity::from_npub(&target).expect("target npub");
        let ip = |s: &str| -> Vec<u8> { s.split('.').map(|x| x.parse::<u8>().unwrap()).collect() };
        let (src, dst) = (ip(&src), ip(&dst));
        let ep2 = ep.clone();
        tokio::spawn(async move {
            for seq in 0u8..20 {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                let mut p = vec![0x45, 0, 0, 60, 0, seq, 0, 0, 64, 1, 0, 0];
                p.extend_from_slice(&src); p.extend_from_slice(&dst);
                let c = csum(&p[..20]); p[10..12].copy_from_slice(&c.to_be_bytes());
                let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, seq];
                icmp.extend_from_slice(&[0xcd; 32]);
                let c = csum(&icmp); icmp[2..4].copy_from_slice(&c.to_be_bytes());
                p.extend_from_slice(&icmp);
                let r = ep2.send_batch_to_peer(id, vec![p]).await;
                println!("TX echo request #{} -> {:?}", seq, r.is_ok());
                // nostr-vpn presence probe (application control frame, same payload format as the desktop app)
                let ctrl = format!("NVPN-FIPS-CTRL\0{{\"v\":1,\"frame\":{{\"kind\":\"ping\",\"network_id\":\"cf60ef1e\",\"sent_at\":{}}}}}", 1762000000u64 + seq as u64);
                let r = ep2.send_batch_to_peer(id, vec![ctrl.into_bytes()]).await;
                println!("TX ctrl ping #{} -> {:?}", seq, r.is_ok());
            }
        });
    }
    let mut msgs: Vec<FipsEndpointMessage> = Vec::new();
    while let Some(_n) = ep.recv_batch_into(&mut msgs, 16).await {
        for m in msgs.drain(..) {
            let mut data: Vec<u8> = m.data.as_slice().to_vec();
            println!("RX {} bytes from {}", data.len(), m.source_peer.npub());
            if data.starts_with(b"NVPN-FIPS-CTRL\0") {
                println!("CTRL RX {}", String::from_utf8_lossy(&data[15..]));
                continue;
            }
            if data.len() >= 28 && data[0] >> 4 == 4 && data[9] == 1 && data[(data[0] & 15) as usize * 4] == 8 {
                let ihl = (data[0] & 15) as usize * 4;
                let (a, b) = (data[12..16].to_vec(), data[16..20].to_vec());
                data[12..16].copy_from_slice(&b);
                data[16..20].copy_from_slice(&a);
                data[ihl] = 0;
                data[ihl + 2] = 0; data[ihl + 3] = 0;
                let c = csum(&data[ihl..]);
                data[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
                data[10] = 0; data[11] = 0;
                let c = csum(&data[..ihl]);
                data[10..12].copy_from_slice(&c.to_be_bytes());
                println!("ICMP echo reply -> {}", m.source_peer.npub());
            }
            let _ = ep.send_batch_to_peer(m.source_peer, vec![data]).await;
        }
    }
}

fn csum(d: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < d.len() { sum += u16::from_be_bytes([d[i], d[i + 1]]) as u32; i += 2; }
    if i < d.len() { sum += (d[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
