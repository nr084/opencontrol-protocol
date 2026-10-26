//! Explicitly authorized endpoint integration diagnostic. No lab addresses or credentials.
#[path = "../tls.rs"]
mod tls;
use anyhow::{ensure, Result};
use bytes::Bytes;
use opencontrol_protocol::{
    connection::*,
    crypto::SessionKey,
    datagram::{Datagram, NetworkPacket},
    s2s::*,
    *,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use zeroize::Zeroizing;
struct Control {
    tls: TlsStream<TcpStream>,
    decoder: ProtocolDecoder,
    session: ProtocolSession,
    start: Instant,
}
impl Control {
    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
    async fn send(&mut self, m: ControlMessage) -> Result<()> {
        let b = ProtocolEncoder::new(ProtocolLimits::default())
            .encode(&m, self.session.version().unwrap_or(WireVersion::V4))?;
        tokio::time::timeout(Duration::from_secs(5), self.tls.write_all(&b)).await??;
        self.session
            .observe(self.session.epoch(), Flow::Outgoing, &m, self.now())?;
        Ok(())
    }
    async fn read(&mut self) -> Result<ControlMessage> {
        loop {
            if let Some(f) = self.decoder.next_frame()? {
                let m = ControlMessage::decode(
                    f,
                    self.session.version().unwrap_or(WireVersion::V4),
                    ProtocolLimits::default(),
                )?;
                self.session
                    .observe(self.session.epoch(), Flow::Incoming, &m, self.now())?;
                return Ok(m);
            }
            let mut b = Zeroizing::new([0; 1]);
            ensure!(self.tls.read(&mut b[..]).await? != 0, "EOF");
            self.decoder.push_bytes(&b[..])?;
        }
    }
    async fn next(&mut self) -> Result<ControlMessage> {
        tokio::time::timeout(Duration::from_secs(5), self.read()).await?
    }
}
fn checksum(b: &[u8]) -> u16 {
    let mut s = 0u32;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 65535) + (s >> 16);
    }
    !(s as u16)
}
fn echo(src: [u8; 4], dst: [u8; 4], seq: u16) -> NetworkPacket {
    let mut b = vec![0; 36];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&36u16.to_be_bytes());
    b[8] = 64;
    b[9] = 1;
    b[12..16].copy_from_slice(&src);
    b[16..20].copy_from_slice(&dst);
    b[20] = 8;
    b[24..26].copy_from_slice(&0x4f43u16.to_be_bytes());
    b[26..28].copy_from_slice(&seq.to_be_bytes());
    b[28..].copy_from_slice(b"OCS2S009");
    let c = checksum(&b[..20]);
    b[10..12].copy_from_slice(&c.to_be_bytes());
    let c = checksum(&b[20..]);
    b[22..24].copy_from_slice(&c.to_be_bytes());
    NetworkPacket {
        ether_type: 0x0800,
        payload: Bytes::from(b),
    }
}
async fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() == 6 && a[1] == "--accept" {
        return accept(&a).await;
    }
    ensure!(
        a.len() == 6,
        "usage: s2s host:port trusted.der client.der key.pk8 aes|legacy"
    );
    let legacy = match a[5].as_str() {
        "aes" => false,
        "legacy" => true,
        _ => anyhow::bail!("cipher argument"),
    };
    let config = tls::pinned_client(
        &std::fs::read(&a[2])?,
        std::fs::read(&a[3])?,
        std::fs::read(&a[4])?,
    )?;
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&a[1])).await??;
    // Brokers can alter TCP peer addresses: bind UDP to the explicit destination separately.
    let name = rustls::pki_types::ServerName::try_from(tcp.peer_addr()?.ip().to_string())?;
    let channel = tokio::time::timeout(
        Duration::from_secs(10),
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await??;
    let l = ProtocolLimits::default();
    let mut c = Control {
        tls: channel.into(),
        decoder: ProtocolDecoder::new(l),
        session: ProtocolSession::new(
            SessionProfile::SiteToSite(EndpointRole::Initiator),
            WireVersion::V4,
            l,
            if legacy {
                LegacyPolicy::ExplicitlyEnabled
            } else {
                LegacyPolicy::Disabled
            },
            0,
            60,
        )?,
        start: Instant::now(),
    };
    ensure!(
        matches!(c.next().await?, ControlMessage::Version(WireVersion::V4)),
        "version"
    );
    c.send(ControlMessage::Version(WireVersion::V4)).await?;
    let ControlMessage::S2sConfig1(ip) = c.next().await? else {
        anyhow::bail!("config1")
    };
    let cipher = if legacy {
        AnyCipherConfig::Legacy(LegacyCipherConfig {
            slot: 0,
            key: LegacyKey::generate()?,
        })
    } else {
        AnyCipherConfig::Aes(CipherConfig {
            slot: 0,
            key: SessionKey::generate()?,
        })
    };
    c.send(ControlMessage::S2sConfig2(IpConfig2::Accepted {
        address: [198, 18, 253, 0],
        netmask: [255, 255, 255, 0],
        cep: 60,
        cipher,
    }))
    .await?;
    let ControlMessage::S2sConfig3(binding) = c.next().await? else {
        anyhow::bail!("config3")
    };
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(&a[1]).await?;
    let addr = udp.peer_addr()?;
    let std::net::IpAddr::V4(address) = addr.ip() else {
        anyhow::bail!("IPv4 peer required")
    };
    let peer = PeerEndpoint {
        address: address.octets(),
        port: addr.port(),
    };
    let e = c.session.epoch();
    c.session.bind_endpoint(e, peer, &binding.secret)?;
    udp.send(&Datagram::Connect(binding.secret).encode(l)?)
        .await?;
    ensure!(
        matches!(c.next().await?, ControlMessage::SecretReceived(_)),
        "binding"
    );
    c.send(ControlMessage::Routes(Routes {
        flags: 3,
        records: vec![],
    }))
    .await?;
    let active = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut b = [0; 8192];
    let mut sent = 0u16;
    let mut replies = 0;
    let mut local_ack = 0;
    let mut peer_rekey = 0;
    let mut proposed = false;
    let mut after_rekey = 0;
    let gateway =
        ((u32::from_be_bytes(ip.address) & u32::from_be_bytes(ip.netmask)) | 1).to_be_bytes();
    while active.elapsed() < Duration::from_secs(72) {
        tokio::select! {
            m=c.read()=>{match m? {
                ControlMessage::KeyChange(_) | ControlMessage::LegacyKeyChange(_)=>{peer_rekey+=1;c.send(ControlMessage::KeyChanged(Bytes::from_static(&[0]))).await?;},
                ControlMessage::KeyChanged(_)=>local_ack+=1,
                ControlMessage::KeepaliveRequest | ControlMessage::Routes(_)=>{},
                _=>anyhow::bail!("unexpected active message"),
            }},
            n=udp.recv(&mut b)=>{let n=n?;if n>=4 && b[1]==0 && b[2]==0 {let p=c.session.open_from(e,peer,Bytes::copy_from_slice(&b[..n]),c.now())?.packet;let d=&p.payload;if p.ether_type==0x0800 && d.len()>=36 && d[9]==1 && d[20]==0 && d[28..36]==*b"OCS2S009" && checksum(&d[20..])==0 {replies+=1;if local_ack>0 && peer_rekey>0 {after_rekey+=1;}}}},
            _=tick.tick()=>{
                c.session.poll(e,c.now())?;ensure!(c.session.active(),"session expired");
                c.send(ControlMessage::KeepaliveRequest).await?;udp.send(&Datagram::Keepalive.encode(l)?).await?;
                let raw=c.session.seal(e,&echo(ip.address,gateway,sent),c.now())?;udp.send(&raw).await?;sent+=1;
                if !proposed && active.elapsed()>Duration::from_secs(10) {let slot=1-c.session.keys().primary_slot().unwrap();c.send(ControlMessage::KeyChange(CipherConfig {slot,key:SessionKey::generate()?})).await?;proposed=true;}
            }
        }
    }
    ensure!(replies>0 && local_ack>0,"acceptance: replies={replies}, local_ack={local_ack}, peer_rekey={peer_rekey}, after={after_rekey}");
    println!(
        "{}",
        serde_json::json!({"passed":true,"library":VERSION,"profile":"s2s-initiator","initial_legacy":legacy,"elapsed_seconds":active.elapsed().as_secs(),"replies":replies,"local_ack":local_ack,"peer_rekey":peer_rekey,"after_both_rekeys":after_rekey})
    );
    Ok(())
}
async fn accept(a: &[String]) -> Result<()> {
    let l = ProtocolLimits::default();
    let config = tls::pinned_server(
        &std::fs::read(&a[3])?,
        std::fs::read(&a[4])?,
        std::fs::read(&a[5])?,
    )?;
    let listener = tokio::net::TcpListener::bind(&a[2]).await?;
    let udp = UdpSocket::bind(&a[2]).await?;
    println!("S2S acceptor listening with explicit certificate pin");
    let (raw, _) = tokio::time::timeout(Duration::from_secs(65), listener.accept()).await??;
    let channel = tokio::time::timeout(
        Duration::from_secs(10),
        TlsAcceptor::from(Arc::new(config)).accept(raw),
    )
    .await??;
    let mut c = Control {
        tls: channel.into(),
        decoder: ProtocolDecoder::new(l),
        session: ProtocolSession::new(
            SessionProfile::SiteToSite(EndpointRole::Acceptor),
            WireVersion::V4,
            l,
            LegacyPolicy::Disabled,
            0,
            60,
        )?,
        start: Instant::now(),
    };
    c.send(ControlMessage::Version(WireVersion::V4)).await?;
    ensure!(
        matches!(c.next().await?, ControlMessage::Version(WireVersion::V4)),
        "version"
    );
    let offered = [198, 18, 254, 2];
    c.send(ControlMessage::S2sConfig1(IpConfig1 {
        address: offered,
        netmask: [255, 255, 255, 0],
    }))
    .await?;
    ensure!(
        matches!(
            c.next().await?,
            ControlMessage::S2sConfig2(IpConfig2::Accepted { .. })
        ),
        "config2"
    );
    let secret = BindingSecret::generate()?;
    c.send(ControlMessage::S2sConfig3(IpConfig3 {
        cep: 60,
        secret: secret.clone(),
    }))
    .await?;
    let mut buffer = [0; 8192];
    let (n, addr) =
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buffer)).await??;
    let Datagram::Connect(received) = Datagram::decode(Bytes::copy_from_slice(&buffer[..n]), l)?
    else {
        anyhow::bail!("binding datagram")
    };
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        anyhow::bail!("IPv4")
    };
    let peer = PeerEndpoint {
        address: ip.octets(),
        port: addr.port(),
    };
    let e = c.session.epoch();
    c.session.bind_endpoint(e, peer, &received)?;
    udp.connect(addr).await?;
    c.send(ControlMessage::SecretReceived(Bytes::from_static(&[0])))
        .await?;
    c.send(ControlMessage::Routes(Routes {
        flags: 3,
        records: vec![],
    }))
    .await?;
    let active = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut sent = 0u16;
    let mut replies = 0;
    let mut peer_rekeys = 0;
    let mut local_ack = 0;
    let mut proposed = false;
    let mut replies_after_both = 0;
    while active.elapsed() < Duration::from_secs(72) {
        tokio::select! {
            m=c.read()=>match m? {
                ControlMessage::KeyChange(_) | ControlMessage::LegacyKeyChange(_)=>{peer_rekeys+=1;c.send(ControlMessage::KeyChanged(Bytes::from_static(&[0]))).await?;},
                ControlMessage::KeyChanged(_)=>local_ack+=1,
                ControlMessage::KeepaliveRequest | ControlMessage::Routes(_)=>{},
                _=>anyhow::bail!("unexpected active message"),
            },
            n=udp.recv(&mut buffer)=>{let n=n?;if n>=4 && buffer[1]==0 && buffer[2]==0 {let p=c.session.open_from(e,peer,Bytes::copy_from_slice(&buffer[..n]),c.now())?.packet;let d=&p.payload;if p.ether_type==0x0800 && d.len()>=36 && d[9]==1 && d[20]==0 && d[28..36]==*b"OCS2S009" && checksum(&d[20..])==0 {replies+=1;if local_ack>0 && peer_rekeys>0 {replies_after_both+=1;}}}},
            _=tick.tick()=>{
                c.session.poll(e,c.now())?;ensure!(c.session.active(),"session expired");c.send(ControlMessage::KeepaliveRequest).await?;udp.send(&Datagram::Keepalive.encode(l)?).await?;
                let raw=c.session.seal(e,&echo([198,18,254,1],offered,sent),c.now())?;udp.send(&raw).await?;sent+=1;
                if !proposed && active.elapsed()>Duration::from_secs(10) && c.session.keys().peer_pending_slot().is_none() {let slot=1-c.session.keys().primary_slot().unwrap();c.send(ControlMessage::KeyChange(CipherConfig {slot,key:SessionKey::generate()?})).await?;proposed=true;}
            }
        }
    }
    ensure!(replies>0 && peer_rekeys>0 && local_ack>0 && replies_after_both>0,"acceptance replies={replies},peer={peer_rekeys},local={local_ack},after={replies_after_both}");
    println!(
        "{}",
        serde_json::json!({"passed":true,"library":VERSION,"profile":"s2s-acceptor","elapsed_seconds":active.elapsed().as_secs(),"replies":replies,"peer_rekeys":peer_rekeys,"local_ack":local_ack,"replies_after_both":replies_after_both})
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("S2S integration failed: {e}");
        std::process::exit(1);
    }
}
