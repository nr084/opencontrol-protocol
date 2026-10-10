use bytes::Bytes;
use opencontrol_protocol::{
    crypto::{ReplayWindow, SessionKey},
    datagram::*,
    *,
};
use proptest::prelude::*;
fn limits() -> ProtocolLimits {
    ProtocolLimits::default()
}
fn frame(opcode: u8, payload: impl Into<Bytes>) -> ControlFrame {
    ControlFrame {
        opcode,
        payload: payload.into(),
    }
}
fn decode(bytes: &[u8]) -> ControlFrame {
    let mut d = ProtocolDecoder::new(limits());
    assert_eq!(d.push_bytes(bytes).unwrap(), bytes.len());
    let f = d.next_frame().unwrap().unwrap();
    d.finish().unwrap();
    f
}

#[test]
fn committed_golden_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../protocol/vectors/synthetic.json")).unwrap();
    for v in vectors["vectors"].as_array().unwrap() {
        if let Some(s) = v["expected_hex"].as_str() {
            let b = hex::decode(s).unwrap();
            if v["name"] == "udp_keepalive" {
                assert_eq!(
                    Datagram::decode(Bytes::from(b.clone()), limits())
                        .unwrap()
                        .encode(limits())
                        .unwrap()
                        .as_ref(),
                    b
                );
            } else {
                let f = decode(&b);
                let m = ControlMessage::decode(f, WireVersion::V4, limits()).unwrap();
                assert_eq!(
                    ProtocolEncoder::new(limits())
                        .encode(&m, WireVersion::V4)
                        .unwrap()
                        .as_ref(),
                    b
                );
            }
        } else {
            let b = hex::decode(v["expected_datagram_hex"].as_str().unwrap()).unwrap();
            let Datagram::Data(d) = Datagram::decode(Bytes::from(b.clone()), limits()).unwrap()
            else {
                panic!()
            };
            let mut cipher =
                DataCipher::new(SessionKey::from_bytes([0; 16]), 0, WireVersion::V2).unwrap();
            assert_eq!(
                cipher.open(&d, limits()).unwrap(),
                NetworkPacket {
                    ether_type: 0x0800,
                    payload: Bytes::new()
                }
            );
            assert_eq!(Datagram::Data(d).encode(limits()).unwrap().as_ref(), b);
        }
    }
}
#[test]
fn fixtures_and_negative_fixtures() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/fixtures");
    for entry in std::fs::read_dir(root.join("control")).unwrap() {
        let b = std::fs::read(entry.unwrap().path()).unwrap();
        let f = decode(&b);
        let m = ControlMessage::decode(f, WireVersion::V4, limits()).unwrap();
        assert_eq!(
            ProtocolEncoder::new(limits())
                .encode(&m, WireVersion::V4)
                .unwrap()
                .as_ref(),
            b
        );
    }
    for entry in std::fs::read_dir(root.join("negative")).unwrap() {
        let b = std::fs::read(entry.unwrap().path()).unwrap();
        let mut d = ProtocolDecoder::new(limits());
        assert!(d.push_bytes(&b).is_err() || d.finish().is_err());
    }
}
#[test]
fn fragmented_and_coalesced_stream() {
    let b = hex::decode("4b050016044b050003004b05000a00").unwrap();
    for split in 0..=b.len() {
        let mut d = ProtocolDecoder::new(limits());
        let mut frames = Vec::new();
        for chunk in [&b[..split], &b[split..]] {
            let mut rest = chunk;
            while !rest.is_empty() {
                let n = d.push_bytes(rest).unwrap();
                rest = &rest[n..];
                if let Some(f) = d.next_frame().unwrap() {
                    frames.push(f);
                }
                assert!(n > 0);
            }
        }
        assert_eq!(
            frames.iter().map(|f| f.opcode).collect::<Vec<_>>(),
            [22, 3, 10]
        );
        d.finish().unwrap();
    }
}
#[test]
fn malformed_typed_messages() {
    for (op, p) in [
        (22, vec![5]),
        (1, vec![1]),
        (2, vec![0, 0]),
        (3, vec![1, 0, 5, 0]),
        (3, vec![0, 1]),
        (5, vec![0; 23]),
        (6, vec![0; 146]),
        (8, vec![0; 21]),
        (10, vec![1]),
        (19, vec![0, 2, 0]),
    ] {
        assert!(ControlMessage::decode(frame(op, p), WireVersion::V4, limits()).is_err());
    }
    let m = ControlMessage::decode(frame(200, vec![1, 2]), WireVersion::V4, limits()).unwrap();
    assert!(matches!(m, ControlMessage::Unknown(_)));
}
#[test]
fn bounds_and_poisoning() {
    let mut d = ProtocolDecoder::new(limits());
    assert!(d.push_bytes(&[0, 5, 0, 22, 4]).is_err());
    assert_eq!(d.push_bytes(&[]), Err(ProtocolError::DecoderPoisoned));
    for length in [0u16, 4, 64000, 65535] {
        let mut d = ProtocolDecoder::new(limits());
        assert!(d
            .push_bytes(&[0x4b, length as u8, (length >> 8) as u8])
            .is_err());
    }
    let f = frame(200, vec![0; 63995]);
    let bytes = ProtocolEncoder::new(limits()).encode_frame(&f).unwrap();
    assert_eq!(decode(&bytes), f);
    let small = ProtocolLimits {
        max_frame_size: 5,
        ..limits()
    };
    assert!(ProtocolEncoder::new(small)
        .encode_frame(&frame(200, vec![0; 2]))
        .is_err());
}
#[test]
fn replay_window_boundaries() {
    let mut w = ReplayWindow::default();
    assert!(w.accept(0).is_err());
    w.accept(1).unwrap();
    w.accept(2).unwrap();
    assert!(w.accept(1).is_err());
    w.accept(100).unwrap();
    w.accept(37).unwrap();
    assert!(w.accept(36).is_err());
    assert!(w.accept(37).is_err());
    assert!(w.accept(0xffff_ffc0).is_err());
    w.accept(0xffff_ffbf).unwrap();
}
#[test]
fn authenticated_data_bad_tag_wrong_slot_and_replay() {
    for v in [
        WireVersion::V1,
        WireVersion::V2,
        WireVersion::V3,
        WireVersion::V4,
    ] {
        let mut tx = DataCipher::new(SessionKey::from_bytes([7; 16]), 0, v).unwrap();
        let mut rx = DataCipher::new(SessionKey::from_bytes([7; 16]), 0, v).unwrap();
        let packet = NetworkPacket {
            ether_type: 0x0800,
            payload: Bytes::from_static(b"test"),
        };
        let d = tx.seal(&packet, limits()).unwrap();
        let mut bad = d.clone();
        bad.tag[0] ^= 1;
        assert_eq!(rx.open(&bad, limits()), Err(ProtocolError::CryptoFailure));
        bad = d.clone();
        bad.slot = 1;
        assert!(rx.open(&bad, limits()).is_err());
        let mut wrong = DataCipher::new(SessionKey::from_bytes([8; 16]), 0, v).unwrap();
        assert_eq!(wrong.open(&d, limits()), Err(ProtocolError::CryptoFailure));
        assert_eq!(rx.open(&d, limits()).unwrap(), packet);
        if v != WireVersion::V1 {
            assert_eq!(rx.open(&d, limits()), Err(ProtocolError::Replay));
        }
    }
}
fn initial(v: WireVersion) -> ControlMessage {
    ControlMessage::InitialConfig(InitialConfig {
        cep: 60,
        metadata: matches!(v, WireVersion::V3 | WireVersion::V4).then_some(ClientMetadata {
            version: [0, 1, 0],
            build: 1,
            os_code: 2,
            description: [0; 128],
        }),
        cipher: CipherConfig {
            slot: 0,
            key: SessionKey::from_bytes([9; 16]),
        },
    })
}
fn ip(v: WireVersion) -> ControlMessage {
    ControlMessage::IpConfig(Box::new(IpConfig {
        address: [10, 0, 0, 2],
        netmask: [255, 255, 255, 0],
        cep: 60,
        dns: [[10, 0, 0, 1], [0; 4]],
        extended: matches!(v, WireVersion::V3 | WireVersion::V4).then_some(ExtendedIpConfig {
            domain: [0; 256],
            wins: [[0; 4]; 2],
        }),
        flags: (v == WireVersion::V4).then_some(0),
        secret: BindingSecret([3; 128]),
    }))
}
#[test]
fn version_dependent_roundtrips() {
    for v in [
        WireVersion::V1,
        WireVersion::V2,
        WireVersion::V3,
        WireVersion::V4,
    ] {
        for m in [initial(v), ip(v)] {
            let bytes = ProtocolEncoder::new(limits()).encode(&m, v).unwrap();
            let m = ControlMessage::decode(decode(&bytes), v, limits()).unwrap();
            assert_eq!(ProtocolEncoder::new(limits()).encode(&m, v).unwrap(), bytes);
        }
    }
}
#[test]
fn handshake_rekey_unknown_and_invalid_transition() {
    use Direction::*;
    for role in [Role::Server, Role::Client] {
        let mut s = StateMachine::new(role);
        let v = WireVersion::V4;
        let events = [
            (ClientToServer, ControlMessage::Version(v)),
            (ServerToClient, ControlMessage::Version(v)),
            (
                ClientToServer,
                ControlMessage::Username(
                    Credential::new(Bytes::from_static(b"test"), limits()).unwrap(),
                ),
            ),
            (ServerToClient, ControlMessage::Ok(vec![])),
            (
                ClientToServer,
                ControlMessage::Password(
                    Credential::new(Bytes::from_static(b"test"), limits()).unwrap(),
                ),
            ),
            (ServerToClient, ControlMessage::Ok(vec![])),
            (ClientToServer, initial(v)),
            (ServerToClient, ip(v)),
            (
                ServerToClient,
                ControlMessage::SecretReceived(Bytes::from_static(&[0])),
            ),
        ];
        for (direction, m) in events {
            s.observe(direction, &m).unwrap();
        }
        assert_eq!(s.state(), ProtocolState::Active);
        for slot in [1, 0] {
            s.observe(
                ClientToServer,
                &ControlMessage::KeyChange(CipherConfig {
                    slot,
                    key: SessionKey::from_bytes([1; 16]),
                }),
            )
            .unwrap();
        }
        s.observe(
            ServerToClient,
            &ControlMessage::KeyChanged(Bytes::from_static(&[0])),
        )
        .unwrap();
        assert_eq!(s.primary_slot(), Some(0));
        s.observe(
            ServerToClient,
            &ControlMessage::Unknown(frame(200, vec![0])),
        )
        .unwrap();
        assert!(s
            .observe(ClientToServer, &ControlMessage::Version(v))
            .is_err());
        assert_eq!(s.state(), ProtocolState::Active);
        s.close();
        assert!(s
            .observe(
                ServerToClient,
                &ControlMessage::KeepaliveResponse(Bytes::from_static(&[0]))
            )
            .is_err());
    }
}
#[test]
fn secrets_are_redacted() {
    let c = Credential::new(Bytes::from_static(b"password-marker"), limits()).unwrap();
    assert!(!format!("{c:?}").contains("marker"));
    let mut d = ProtocolDecoder::new(limits());
    d.push_bytes(b"K\x20\0\x02password-marker").unwrap();
    assert!(!format!("{d:?}").contains("marker"));
}

#[test]
fn committed_handshake_transcript() {
    let mut data = include_bytes!("../../../protocol/vectors/handshake_v4.bin").as_slice();
    let mut state = StateMachine::new(Role::Server);
    while !data.is_empty() {
        assert!(data.len() >= 4);
        let direction = if data[0] == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let length = u16::from_le_bytes([data[2], data[3]]) as usize;
        let frame = frame(data[1], Bytes::copy_from_slice(&data[4..4 + length]));
        let message =
            ControlMessage::decode(frame, state.version().unwrap_or(WireVersion::V4), limits())
                .unwrap();
        state.observe(direction, &message).unwrap();
        data = &data[4 + length..];
    }
    assert_eq!(state.state(), ProtocolState::Active);
    assert_eq!(state.primary_slot(), Some(1));
}
proptest! {
    #[test]
    fn routes_and_extensions_roundtrip(flags in any::<u8>(), records in proptest::collection::vec((any::<[u8;4]>(),any::<[u8;4]>()),0..50),values in proptest::collection::vec(proptest::collection::vec(any::<u8>(),0..100),0..20)) {
        for m in [ControlMessage::Routes(Routes {flags,records:records.into_iter().map(|(network,netmask)|Route {network,netmask}).collect()}),
            ControlMessage::Ok(values.into_iter().map(|value|Extension {kind:1,value:Bytes::from(value)}).collect())] {
            let b = ProtocolEncoder::new(limits()).encode(&m,WireVersion::V4).unwrap();
            let parsed = ControlMessage::decode(decode(&b),WireVersion::V4,limits()).unwrap();
            prop_assert_eq!(ProtocolEncoder::new(limits()).encode(&parsed,WireVersion::V4).unwrap(),b);
        }
    }
    #[test]
    fn unknown_frame_roundtrip(payload in proptest::collection::vec(any::<u8>(),1..1024),chunk_size in 1usize..32) {
        let f = frame(200,payload); let b = ProtocolEncoder::new(limits()).encode_frame(&f).unwrap(); let mut d = ProtocolDecoder::new(limits());
        for chunk in b.chunks(chunk_size) { prop_assert_eq!(d.push_bytes(chunk).unwrap(),chunk.len()); }
        prop_assert_eq!(d.next_frame().unwrap().unwrap(),f); prop_assert!(d.finish().is_ok());
    }
    #[test]
    fn arbitrary_input_does_not_panic(bytes in proptest::collection::vec(any::<u8>(),0..2048)) {
        let mut d = ProtocolDecoder::new(limits()); let _ = d.push_bytes(&bytes); let _ = d.next_frame(); let _ = d.finish();
        let _ = Datagram::decode(Bytes::from(bytes.clone()),limits());
        for opcode in [1,2,3,5,6,8,19,22,200] { let _ = ControlMessage::decode(frame(opcode,bytes.clone()),WireVersion::V4,limits()); }
    }
}
