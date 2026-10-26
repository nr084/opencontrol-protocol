//! Authorized diagnostic only. All wire parsing, crypto and route semantics use the library.
mod tls;
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use opencontrol_protocol::{
    crypto::SessionKey,
    datagram::{Datagram, NetworkPacket},
    session::KeySlots,
    *,
};
use std::{
    io::{BufRead, Read},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use zeroize::Zeroizing;

struct Control {
    socket: TlsStream<TcpStream>,
    decoder: ProtocolDecoder,
    machine: StateMachine,
    limits: ProtocolLimits,
}
impl Control {
    async fn send(&mut self, m: ControlMessage) -> Result<()> {
        let b = ProtocolEncoder::new(self.limits)
            .encode(&m, self.machine.version().unwrap_or(WireVersion::V4))?;
        tokio::time::timeout(Duration::from_secs(10), self.socket.write_all(&b)).await??;
        self.machine.outgoing(&m)?;
        Ok(())
    }
    async fn read(&mut self) -> Result<ControlMessage> {
        loop {
            if let Some(frame) = self.decoder.next_frame()? {
                let m = ControlMessage::decode(
                    frame,
                    self.machine.version().unwrap_or(WireVersion::V4),
                    self.limits,
                )?;
                self.machine.incoming(&m).with_context(|| {
                    format!(
                        "incoming opcode {} in {:?}",
                        m.opcode(),
                        self.machine.state()
                    )
                })?;
                return Ok(m);
            }
            let mut byte = Zeroizing::new([0; 1]);
            let n = self.socket.read(&mut byte[..]).await?;
            ensure!(n != 0, "control EOF");
            self.decoder.push_bytes(&byte[..])?;
        }
    }
    async fn next(&mut self) -> Result<ControlMessage> {
        tokio::time::timeout(Duration::from_secs(15), self.read()).await?
    }
}
fn log(value: serde_json::Value) {
    println!("{value}");
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for b in bytes.chunks(2) {
        sum += u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn echo(src: [u8; 4], dst: [u8; 4], sequence: u16) -> NetworkPacket {
    let mut b = vec![0; 36];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&36u16.to_be_bytes());
    b[8] = 64;
    b[9] = 1;
    b[12..16].copy_from_slice(&src);
    b[16..20].copy_from_slice(&dst);
    b[20] = 8;
    b[24..26].copy_from_slice(&0x4f43u16.to_be_bytes());
    b[26..28].copy_from_slice(&sequence.to_be_bytes());
    b[28..].copy_from_slice(b"OCROUTES");
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
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--check-tls" {
        let certificate = std::fs::read(&args[3])?;
        let config = tls::pinned(&certificate)?;
        let tcp =
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&args[2])).await??;
        let name = rustls::pki_types::ServerName::try_from(tcp.peer_addr()?.ip().to_string())?;
        let _tls = tokio::time::timeout(
            Duration::from_secs(15),
            TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await??;
        log(
            serde_json::json!({"event":"tls_preflight","trusted_leaf_and_signature_verified":true,"application_credentials_sent":false}),
        );
        return Ok(());
    }
    ensure!(args.len()==4,"usage: oc-routes-live host:port trusted-leaf.der duration-seconds; username and password on stdin");
    let duration = args[3].parse::<u64>()?;
    ensure!(
        (1260..=7200).contains(&duration),
        "duration must be1260..7200s"
    );
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut username = Zeroizing::new(String::new());
    let mut password = Zeroizing::new(String::new());
    input.by_ref().take(4097).read_line(&mut username)?;
    input.by_ref().take(4097).read_line(&mut password)?;
    ensure!(
        username.len() <= 4096 && password.len() <= 4096,
        "credential limit"
    );
    let user = username.trim_end_matches(['\r', '\n']);
    let pass = password.trim_end_matches(['\r', '\n']);
    ensure!(!user.is_empty() && !pass.is_empty(), "credentials missing");
    let limits = ProtocolLimits::default();
    let certificate = std::fs::read(&args[2])?;
    let config = tls::pinned(&certificate)?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&args[1]))
        .await?
        .context("TCP connect failed")?;
    let peer = tcp.peer_addr()?;
    let local = tcp.local_addr()?;
    let name = rustls::pki_types::ServerName::try_from(peer.ip().to_string())?;
    let socket = tokio::time::timeout(
        Duration::from_secs(15),
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await??;
    let mut io = Control {
        socket,
        decoder: ProtocolDecoder::new(limits),
        machine: StateMachine::new(Role::Client),
        limits,
    };
    log(serde_json::json!({"event":"tls_ready","trusted_leaf_verified":true}));
    io.send(ControlMessage::Version(WireVersion::V4)).await?;
    ensure!(
        matches!(io.next().await?, ControlMessage::Version(WireVersion::V4)),
        "version rejected"
    );
    io.send(ControlMessage::Username(Credential::new(
        Bytes::copy_from_slice(user.as_bytes()),
        limits,
    )?))
    .await?;
    ensure!(
        matches!(io.next().await?, ControlMessage::Ok(_)),
        "username rejected"
    );
    io.send(ControlMessage::Password(Credential::new(
        Bytes::copy_from_slice(pass.as_bytes()),
        limits,
    )?))
    .await?;
    ensure!(
        matches!(io.next().await?, ControlMessage::Ok(_)),
        "authentication rejected"
    );
    drop(password);
    log(serde_json::json!({"event":"authenticated"}));
    drop(username);
    drop(input);
    let key = SessionKey::generate()?;
    let mut keys = KeySlots::new(WireVersion::V4, LegacyPolicy::Disabled)?;
    let epoch = keys.epoch();
    keys.install_initial(
        epoch,
        &AnyCipherConfig::Aes(CipherConfig {
            slot: 0,
            key: SessionKey::from_bytes(*key.as_bytes()),
        }),
    )?;
    let mut description = [0; 128];
    description[..22].copy_from_slice(b"OpenControl routes lab");
    io.send(ControlMessage::InitialConfig(InitialConfig {
        cep: 1800,
        metadata: Some(ClientMetadata {
            version: [0, 9, 0],
            build: 1,
            os_code: 2,
            description,
        }),
        cipher: CipherConfig { slot: 0, key },
    }))
    .await?;
    let ControlMessage::IpConfig(ip) = io.next().await? else {
        anyhow::bail!("IP configuration missing")
    };
    ensure!(ip.cep >= 2, "invalid CEP");
    log(serde_json::json!({"event":"ip_config_received","cep":ip.cep}));
    // Desktop TCP brokers may expose IPv6 loopback as the local TCP endpoint.
    // UDP must use a real IPv4 interface, not that broker loopback.
    let bind_ip = if local.ip().is_ipv4() && !local.ip().is_loopback() {
        local.ip()
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    let udp = UdpSocket::bind((bind_ip, 0))
        .await
        .context("UDP bind failed")?;
    udp.connect(&args[1]).await.context("UDP connect failed")?;
    udp.send(&Datagram::Connect(ip.secret.clone()).encode(limits)?)
        .await?;
    ensure!(
        matches!(io.next().await?, ControlMessage::SecretReceived(_)),
        "UDP binding rejected"
    );
    let ControlMessage::Routes(first) = io.next().await? else {
        anyhow::bail!("initial ROUTES missing")
    };
    let mut routes = RouteState::new(limits);
    ensure!(
        matches!(routes.apply(&first)?, RouteUpdate::Changed(_)),
        "initial routes result"
    );
    let start = Instant::now();
    let gateway =
        ((u32::from_be_bytes(ip.address) & u32::from_be_bytes(ip.netmask)) | 1).to_be_bytes();
    let mut periodic = 0;
    let mut changed = 1;
    let mut sent = 0u64;
    let mut replies = 0u64;
    let mut keepalives = 0u64;
    let mut rotations = 0u64;
    let mut last_control = Instant::now();
    let mut last_request = Instant::now();
    let mut last_data = Instant::now() - Duration::from_secs(5);
    let mut last_rotation = Instant::now();
    let mut pending_since = None;
    let mut last_report = Instant::now();
    let mut last_reply = None;
    let mut post_update_reply = false;
    let mut periodic_times = Vec::new();
    log(
        serde_json::json!({"event":"started","library":VERSION,"duration_seconds":duration,"flags":first.flags,"count":first.records.len(),"cep":ip.cep,"state":"Active"}),
    );
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut buffer = [0; 8192];
    while start.elapsed() < Duration::from_secs(duration) {
        tokio::select! {
            m=io.read()=> {
                last_control=Instant::now();
                match m? {
                    ControlMessage::Routes(m)=> {
                        let primary=io.machine.primary_slot();let pending=io.machine.pending_slot();
                        let differs=matches!(routes.apply(&m)?,RouteUpdate::Changed(_));
                        ensure!(io.machine.state()==ProtocolState::Active && io.machine.primary_slot()==primary && io.machine.pending_slot()==pending,"ROUTES changed session slots");
                        if differs {changed+=1;} else {periodic+=1;periodic_times.push(start.elapsed().as_secs());}
                        post_update_reply=false;
                        log(serde_json::json!({"event":"routes","elapsed_seconds":start.elapsed().as_secs_f64(),"flags":m.flags,"count":m.records.len(),"changed":differs,"primary":primary,"pending":pending,"traffic_replies":replies}));
                    },
                    ControlMessage::KeepaliveResponse(_)=>keepalives+=1,
                    ControlMessage::KeyChanged(_)=>{keys.acknowledge_local(epoch)?;pending_since=None;rotations+=1;},
                    ControlMessage::Unknown(_) | ControlMessage::Ok(_) | ControlMessage::Error(_) | ControlMessage::Version(_) | ControlMessage::KeepaliveRequest | ControlMessage::Failure(_)=>{},
                    _=>anyhow::bail!("unexpected active message"),
                }
            },
            n=udp.recv(&mut buffer)=> {
                let n=n?;
                if n>=4 && buffer[1]==0 && buffer[2]==0 {
                    let packet=keys.open(epoch,Bytes::copy_from_slice(&buffer[..n]),limits)?.packet;
                    let b=&packet.payload;
                    if packet.ether_type==0x0800 && b.len()>=36 && b[0]==0x45 && b[9]==1 && b[20]==0 && b[24..26]==0x4f43u16.to_be_bytes() && b[28..36]==*b"OCROUTES" && b[12..16]==gateway && b[16..20]==ip.address && checksum(&b[20..])==0 {
                        replies+=1;last_reply=Some(Instant::now());post_update_reply=true;
                    }
                }
            },
            _=tick.tick()=> {
                ensure!(last_control.elapsed()<Duration::from_secs(120),"control timeout");
                ensure!(pending_since.is_none_or(|t:Instant|t.elapsed()<Duration::from_secs(20)),"rekey acknowledgment timeout");
                if last_request.elapsed()>=Duration::from_secs(30) {io.send(ControlMessage::KeepaliveRequest).await?;last_request=Instant::now();}
                if last_data.elapsed()>=Duration::from_secs(5) {
                    udp.send(&Datagram::Keepalive.encode(limits)?).await?;
                    let data=keys.seal(epoch,&echo(ip.address,gateway,sent as u16),limits)?;
                    udp.send(&data).await?;sent+=1;last_data=Instant::now();
                }
                let slot=io.machine.primary_slot().context("no primary")? as usize;
                if pending_since.is_none() && (last_rotation.elapsed()>=Duration::from_secs(u64::from(ip.cep)/2) || keys.needs_rotation()) {
                    let next=1-slot;let key=SessionKey::generate()?;
                    keys.propose(epoch,&AnyCipherConfig::Aes(CipherConfig {slot:next as u8,key:SessionKey::from_bytes(*key.as_bytes())}))?;
                    io.send(ControlMessage::KeyChange(CipherConfig {slot:next as u8,key})).await?;last_rotation=Instant::now();pending_since=Some(last_rotation);
                }
                if last_report.elapsed()>=Duration::from_secs(60) {log(serde_json::json!({"event":"progress","elapsed_seconds":start.elapsed().as_secs(),"sent":sent,"replies":replies,"periodic_unchanged":periodic,"rekeys":rotations}));last_report=Instant::now();}
            },
        }
    }
    let expected_periodic = duration / 600;
    let passed = periodic >= expected_periodic
        && replies > 0
        && post_update_reply
        && last_reply.is_some_and(|t| t.elapsed() < Duration::from_secs(15))
        && io.machine.state() == ProtocolState::Active;
    log(
        serde_json::json!({"event":"summary","passed":passed,"elapsed_seconds":start.elapsed().as_secs_f64(),"periodic_unchanged":periodic,"expected_periodic":expected_periodic,"periodic_times":periodic_times,"platform_changes":changed,"sent":sent,"replies":replies,"keepalive_responses":keepalives,"rekeys":rotations,"reconnects":0,"state":"Active","actual_wall_clock":true,"os_route_application":false}),
    );
    ensure!(passed, "live acceptance criteria not met");
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        log(serde_json::json!({"event":"failed","passed":false,"reason":error.to_string()}));
        std::process::exit(1);
    }
}
