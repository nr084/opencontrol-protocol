use bytes::Bytes;
use opencontrol_protocol::{
    connection::*,
    crypto::SessionKey,
    datagram::NetworkPacket,
    liveness::*,
    route_application::*,
    routes::{advertisement_batches, RouteProfile},
    s2s::*,
    session::*,
    *,
};

fn aes(slot: u8, byte: u8) -> AnyCipherConfig {
    AnyCipherConfig::Aes(CipherConfig {
        slot,
        key: SessionKey::from_bytes([byte; 16]),
    })
}
fn r(n: u8) -> Route {
    Route {
        network: [10, n, 0, 0],
        netmask: [255, 255, 0, 0],
    }
}
fn routes(flags: u8, records: Vec<Route>) -> Routes {
    Routes { flags, records }
}
fn endpoint(role: EndpointRole) -> ProtocolSession {
    let mut s = ProtocolSession::new(
        SessionProfile::SiteToSite(role),
        WireVersion::V4,
        ProtocolLimits::default(),
        LegacyPolicy::Disabled,
        0,
        1800,
    )
    .unwrap();
    let epoch = s.epoch();
    let acceptor = if role == EndpointRole::Initiator {
        Flow::Incoming
    } else {
        Flow::Outgoing
    };
    let initiator = if acceptor == Flow::Incoming {
        Flow::Outgoing
    } else {
        Flow::Incoming
    };
    for (flow, m) in [
        (acceptor, ControlMessage::Version(WireVersion::V4)),
        (initiator, ControlMessage::Version(WireVersion::V4)),
        (
            acceptor,
            ControlMessage::S2sConfig1(IpConfig1 {
                address: [10, 0, 0, 0],
                netmask: [255, 255, 255, 0],
            }),
        ),
        (
            initiator,
            ControlMessage::S2sConfig2(IpConfig2::Accepted {
                address: [10, 1, 0, 0],
                netmask: [255, 255, 255, 0],
                cep: 1800,
                cipher: aes(0, 1),
            }),
        ),
        (
            acceptor,
            ControlMessage::S2sConfig3(IpConfig3 {
                cep: 1800,
                secret: BindingSecret([19; 128]),
            }),
        ),
        (
            acceptor,
            ControlMessage::SecretReceived(Bytes::from_static(&[0])),
        ),
    ] {
        s.observe(epoch, flow, &m, 0).unwrap();
    }
    assert!(s.active());
    s
}
fn ack(app: &mut RouteApplications, plan: &ApplicationPlan) {
    app.acknowledge(plan.id(), &vec![true; plan.operations().len()], true)
        .unwrap();
}

fn client() -> ProtocolSession {
    client_server(Role::Client)
}
fn client_server(role: Role) -> ProtocolSession {
    let l = ProtocolLimits::default();
    let mut s = ProtocolSession::new(
        SessionProfile::ClientServer(role),
        WireVersion::V4,
        l,
        LegacyPolicy::Disabled,
        0,
        1800,
    )
    .unwrap();
    let e = s.epoch();
    let mut b = include_bytes!("../../../protocol/vectors/handshake_v4.bin").as_slice();
    while !b.is_empty() {
        let flow = if (b[0] == 0) == (role == Role::Client) {
            Flow::Outgoing
        } else {
            Flow::Incoming
        };
        let n = u16::from_le_bytes([b[2], b[3]]) as usize;
        let mut m = ControlMessage::decode(
            ControlFrame {
                opcode: b[1],
                payload: Bytes::copy_from_slice(&b[4..4 + n]),
            },
            WireVersion::V4,
            l,
        )
        .unwrap();
        if let ControlMessage::IpConfig(ip) = &mut m {
            ip.cep = 1800;
        }
        s.observe(e, flow, &m, 0).unwrap();
        b = &b[4 + n..];
    }
    assert!(s.active());
    s
}

#[test]
fn server_role_refreshes_on_requests_and_does_not_schedule_client_keepalive() {
    let mut s = client_server(Role::Server);
    let e = s.epoch();
    for n in 1..=4 {
        s.observe(
            e,
            Flow::Incoming,
            &ControlMessage::KeepaliveRequest,
            n * 60_000,
        )
        .unwrap();
        let events = s.poll(e, n * 60_000).unwrap();
        assert!(!events.control_keepalive_due);
        assert!(events.close.is_none());
    }
    assert!(s.active());
}

#[test]
fn newly_owned_secrets_are_redacted_in_diagnostics() {
    let l = ProtocolLimits::default();
    let password = "secret-debug-marker-unique";
    let m = ControlMessage::Password(Credential::from_utf8(password, l).unwrap());
    assert!(!format!("{m:?}").contains(password));
    let key = LegacyKey::from_bytes([113; 16], [117; 8]);
    let debug = format!("{key:?}");
    assert!(!debug.contains("113"));
    assert!(!debug.contains("117"));
    let c = ControlMessage::S2sConfig3(IpConfig3 {
        cep: 60,
        secret: BindingSecret([119; 128]),
    });
    assert!(!format!("{c:?}").contains("119"));
    let mut slots = KeySlots::new(WireVersion::V4, LegacyPolicy::Disabled).unwrap();
    slots.install_initial(slots.epoch(), &aes(0, 123)).unwrap();
    assert!(!format!("{slots:?}").contains("123, 123"));
}

#[test]
fn native_peer_can_replace_current_slot_but_data_waits_for_sent_ack() {
    let mut s = endpoint(EndpointRole::Acceptor);
    let e = s.epoch();
    let p = PeerEndpoint {
        address: [192, 0, 2, 1],
        port: 4090,
    };
    s.bind_endpoint(e, p, &BindingSecret([19; 128])).unwrap();
    let packet = NetworkPacket {
        ether_type: 0x0800,
        payload: Bytes::from_static(b"replacement"),
    };
    let AnyCipherConfig::Aes(c) = aes(0, 2) else {
        unreachable!()
    };
    assert!(matches!(
        s.observe(e, Flow::Incoming, &ControlMessage::KeyChange(c), 1)
            .unwrap(),
        SessionEvent::KeyInstalled {
            slot: 0,
            ack_required: true
        }
    ));
    assert_eq!(s.keys().generation(0), Some(2));
    assert_eq!(s.seal(e, &packet, 1), Err(ProtocolError::RekeyPending));
    s.observe(
        e,
        Flow::Outgoing,
        &ControlMessage::KeyChanged(Bytes::from_static(&[0])),
        2,
    )
    .unwrap();
    let raw = s.seal(e, &packet, 2).unwrap();
    let mut peer = KeySlots::new(WireVersion::V4, LegacyPolicy::Disabled).unwrap();
    let pe = peer.epoch();
    peer.install_initial(pe, &aes(0, 2)).unwrap();
    assert_eq!(
        peer.open(pe, raw, ProtocolLimits::default())
            .unwrap()
            .packet,
        packet
    );
}

#[test]
fn c0019_active_ignores_auth_responses_then_processes_routes() {
    let mut s = client();
    let e = s.epoch();
    let primary = s.keys().primary_slot();
    for (opcode, payload) in [
        (3, vec![0]),
        (4, vec![0xa7]),
        (22, vec![1]),
        (10, vec![0]),
        (11, vec![0]),
    ] {
        let m = ControlMessage::decode(
            ControlFrame {
                opcode,
                payload: Bytes::from(payload),
            },
            WireVersion::V4,
            ProtocolLimits::default(),
        )
        .unwrap();
        s.observe(e, Flow::Incoming, &m, 1).unwrap();
        assert!(s.active());
        assert_eq!(s.keys().primary_slot(), primary);
    }
    let event = s
        .observe(
            e,
            Flow::Incoming,
            &ControlMessage::Routes(routes(7, vec![])),
            2,
        )
        .unwrap();
    assert!(matches!(event, SessionEvent::Routes { .. }));
    assert!(s.active());
    assert!(s.routes().current().unwrap().safe_lan());
    let mut handshake = StateMachine::new(Role::Client);
    assert!(handshake
        .incoming(&ControlMessage::Error(Bytes::from_static(&[0xa7])))
        .is_err());
}

#[test]
fn cep1800_periodic_empty_routes_at_600_before_rekey_preserves_session() {
    let mut s = client();
    let e = s.epoch();
    s.observe(
        e,
        Flow::Incoming,
        &ControlMessage::Routes(routes(7, vec![])),
        0,
    )
    .unwrap();
    for n in 1..=10 {
        s.observe(
            e,
            Flow::Outgoing,
            &ControlMessage::KeepaliveRequest,
            n * 59_700,
        )
        .unwrap();
        s.observe(
            e,
            Flow::Incoming,
            &ControlMessage::KeepaliveResponse(Bytes::from_static(&[0])),
            n * 59_700,
        )
        .unwrap();
    }
    let p = s.keys().primary_slot();
    let g = s.keys().generation(p.unwrap());
    assert!(!s.poll(e, 600_000).unwrap().rekey_due);
    assert_eq!(
        s.observe(
            e,
            Flow::Incoming,
            &ControlMessage::Routes(routes(7, vec![])),
            600_000
        )
        .unwrap(),
        SessionEvent::Routes {
            changed: false,
            complete: true,
            safe_lan_changed: false
        }
    );
    assert!(s.active());
    assert_eq!(s.epoch(), e);
    assert_eq!(s.keys().primary_slot(), p);
    assert_eq!(s.keys().generation(p.unwrap()), g);
}

#[test]
fn missing_ack_terminates_locally_without_waiting_for_eof() {
    let mut s = endpoint(EndpointRole::Initiator);
    let e = s.epoch();
    let AnyCipherConfig::Aes(c) = aes(1, 2) else {
        unreachable!()
    };
    s.observe(e, Flow::Outgoing, &ControlMessage::KeyChange(c), 1)
        .unwrap();
    assert_eq!(
        s.poll(e, 20_001).unwrap().close,
        Some(CloseReason::RekeyTimeout)
    );
    assert_eq!(s.keys().primary_slot(), None);
    assert_eq!(s.close_deadline(), Some(25_001));
}

#[test]
fn s2s_rejection_has_no_cipher_and_success_requires_complete_config() {
    let l = ProtocolLimits::default();
    let mut rejected = vec![0; 13];
    rejected[8] = 2;
    rejected[11] = 99;
    rejected[12] = 88;
    assert!(matches!(
        ControlMessage::decode(
            ControlFrame {
                opcode: 17,
                payload: Bytes::from(rejected.clone())
            },
            WireVersion::V4,
            l
        )
        .unwrap(),
        ControlMessage::S2sConfig2(IpConfig2::Rejected { error: 2, .. })
    ));
    rejected[8] = 0;
    assert!(ControlMessage::decode(
        ControlFrame {
            opcode: 17,
            payload: Bytes::from(rejected)
        },
        WireVersion::V4,
        l
    )
    .is_err());
    for v in [
        WireVersion::V1,
        WireVersion::V2,
        WireVersion::V3,
        WireVersion::V4,
    ] {
        for legacy in [false, true] {
            let metadata = if matches!(v, WireVersion::V3 | WireVersion::V4) {
                Some(ClientMetadata::new([0, 9, 0], 1, 2, "caller supplied").unwrap())
            } else {
                None
            };
            let m = if legacy {
                ControlMessage::LegacyInitialConfig(LegacyInitialConfig {
                    cep: 1800,
                    metadata,
                    cipher: LegacyCipherConfig {
                        slot: 0,
                        key: LegacyKey::from_bytes([1; 16], [2; 8]),
                    },
                })
            } else {
                let AnyCipherConfig::Aes(cipher) = aes(0, 1) else {
                    unreachable!()
                };
                ControlMessage::InitialConfig(InitialConfig {
                    cep: 1800,
                    metadata,
                    cipher,
                })
            };
            let raw = ProtocolEncoder::new(l).encode(&m, v).unwrap();
            let expected = if matches!(v, WireVersion::V3 | WireVersion::V4) {
                if legacy {
                    167
                } else {
                    160
                }
            } else if legacy {
                30
            } else {
                23
            };
            assert_eq!(raw.len(), expected + 4);
            let parsed = ControlMessage::decode(
                ControlFrame {
                    opcode: 5,
                    payload: Bytes::copy_from_slice(&raw[4..]),
                },
                v,
                l,
            )
            .unwrap();
            assert_eq!(ProtocolEncoder::new(l).encode(&parsed, v).unwrap(), raw);
        }
    }
}

#[test]
fn s2s_both_roles_bidirectional_rekey_and_collision() {
    for role in [EndpointRole::Initiator, EndpointRole::Acceptor] {
        let mut s = endpoint(role);
        let e = s.epoch();
        for (i, (flow, slot, byte)) in [(Flow::Outgoing, 1, 2), (Flow::Incoming, 0, 3)]
            .into_iter()
            .enumerate()
        {
            let AnyCipherConfig::Aes(c) = aes(slot, byte) else {
                unreachable!()
            };
            s.observe(e, flow, &ControlMessage::KeyChange(c), i as u64 * 2 + 1)
                .unwrap();
            let reverse = if flow == Flow::Outgoing {
                Flow::Incoming
            } else {
                Flow::Outgoing
            };
            assert!(
                matches!(s.observe(e,reverse,&ControlMessage::KeyChanged(Bytes::from_static(&[0])),i as u64*2+2).unwrap(),SessionEvent::KeyAcknowledged(AckOutcome::Promoted {slot:s,..}) if s==slot)
            );
            assert_eq!(s.keys().primary_slot(), Some(slot));
        }
        let AnyCipherConfig::Aes(c) = aes(1, 4) else {
            unreachable!()
        };
        s.observe(e, Flow::Outgoing, &ControlMessage::KeyChange(c), 5)
            .unwrap();
        let AnyCipherConfig::Aes(c) = aes(1, 5) else {
            unreachable!()
        };
        assert_eq!(
            s.observe(e, Flow::Incoming, &ControlMessage::KeyChange(c), 6),
            Err(ProtocolError::RekeyCollision)
        );
        assert!(!s.active());
        assert_eq!(s.keys().primary_slot(), None);
        assert_eq!(s.close_deadline(), Some(5006));
    }
}

#[test]
fn session_reconnect_clears_binding_keys_routes_and_fences_callbacks() {
    let mut s = endpoint(EndpointRole::Initiator);
    let old = s.epoch();
    let peer = PeerEndpoint {
        address: [192, 0, 2, 1],
        port: 4090,
    };
    s.bind_endpoint(old, peer, &BindingSecret([19; 128]))
        .unwrap();
    s.observe(
        old,
        Flow::Incoming,
        &ControlMessage::Routes(routes(3, vec![r(1)])),
        1,
    )
    .unwrap();
    assert!(s
        .bind_endpoint(
            old,
            PeerEndpoint { port: 4091, ..peer },
            &BindingSecret([19; 128])
        )
        .is_err());
    let new = s.reconnect(2).unwrap();
    assert_ne!(old, new);
    assert!(!s.active());
    assert!(s.peer().is_none());
    assert!(s.routes().current().is_none());
    assert_eq!(s.keys().generation(0), None);
    assert_eq!(
        s.observe(
            old,
            Flow::Incoming,
            &ControlMessage::KeyChanged(Bytes::new()),
            3
        ),
        Err(ProtocolError::StaleSession)
    );
    assert!(s
        .bind_endpoint(new, peer, &BindingSecret([19; 128]))
        .is_err());
}

#[test]
fn old_slot_survives_promotion_then_replacement_retires_it() {
    let limits = ProtocolLimits::default();
    let mut rx = KeySlots::new(WireVersion::V4, LegacyPolicy::Disabled).unwrap();
    let e = rx.epoch();
    let mut old = KeySlots::new(WireVersion::V4, LegacyPolicy::Disabled).unwrap();
    let oe = old.epoch();
    rx.install_initial(e, &aes(0, 1)).unwrap();
    old.install_initial(oe, &aes(0, 1)).unwrap();
    let p = NetworkPacket {
        ether_type: 0x0800,
        payload: Bytes::from_static(b"synthetic"),
    };
    assert_eq!(
        rx.acknowledge_local(e).unwrap(),
        AckOutcome::IgnoredUnsolicited
    );
    rx.propose(e, &aes(1, 2)).unwrap();
    assert_eq!(rx.propose(e, &aes(1, 3)), Err(ProtocolError::RekeyPending));
    rx.acknowledge_local(e).unwrap();
    let b = old.seal(oe, &p, limits).unwrap();
    let mut corrupt = b.to_vec();
    corrupt[16] ^= 1;
    assert!(rx.open(e, Bytes::from(corrupt), limits).is_err());
    assert_eq!(
        rx.open(e, b.clone(), limits).unwrap().integrity,
        Integrity::Authenticated
    );
    assert!(rx.open(e, b, limits).is_err());
    rx.propose(e, &aes(0, 3)).unwrap();
    rx.acknowledge_local(e).unwrap();
    assert_eq!(rx.generation(0), Some(2));
    assert!(rx
        .open(e, old.seal(oe, &p, limits).unwrap(), limits)
        .is_err());
    let newer = rx.reconnect().unwrap();
    assert_eq!(rx.acknowledge_local(e), Err(ProtocolError::StaleSession));
    assert_eq!(rx.primary_slot(), None);
    assert!(rx.install_initial(newer, &aes(0, 4)).is_ok());
}

#[test]
fn conflict_reannouncement_retry_and_failed_delete_keep_ownership() {
    let mut app = RouteApplications::new(ProtocolLimits::default());
    let a = SessionEpoch::generate().unwrap();
    let b = SessionEpoch::generate().unwrap();
    for owner in [a, b] {
        app.register(owner, RouteProfile::Endpoint, None).unwrap();
        app.receive(owner, &routes(3, vec![r(1)])).unwrap();
    }
    let p = app.begin_plan(a).unwrap().unwrap();
    ack(&mut app, &p);
    let p = app.begin_plan(b).unwrap().unwrap();
    assert!(p.operations().is_empty());
    ack(&mut app, &p);
    app.withdraw(a).unwrap();
    let p = app.begin_plan(a).unwrap().unwrap();
    app.acknowledge(p.id(), &[false], true).unwrap();
    assert_eq!(app.applied(a).len(), 1);
    assert!(app.forget(a).is_err());
    let p = app.begin_plan(a).unwrap().unwrap();
    ack(&mut app, &p);
    app.forget(a).unwrap();
    assert!(
        !app.receive(b, &routes(3, vec![r(1)]))
            .unwrap()
            .logical_changed
    );
    let p = app.begin_plan(b).unwrap().unwrap();
    assert_eq!(p.operations().len(), 1);
    app.acknowledge(p.id(), &[false], true).unwrap();
    let p = app.begin_plan(b).unwrap().unwrap();
    ack(&mut app, &p);
    assert_eq!(app.applied(b).len(), 1);
    assert!(app.begin_plan(b).unwrap().is_none());
}

#[test]
fn full_tunnel_endpoint_order_partial_success_split_and_foreign_cleanup() {
    let mut app = RouteApplications::new(ProtocolLimits::default());
    let e = SessionEpoch::generate().unwrap();
    app.register(
        e,
        RouteProfile::Client,
        Some(EndpointBypass {
            address: [192, 0, 2, 1],
            gateway: Some([192, 0, 2, 254]),
            uplink: 7,
        }),
    )
    .unwrap();
    app.register_external(r(99)).unwrap();
    app.receive(e, &routes(15, vec![])).unwrap();
    let p = app.begin_plan(e).unwrap().unwrap();
    assert_eq!(p.operations().len(), 3);
    assert!(matches!(
        &p.operations()[0],
        RouteOperation::Add(OwnedRoute {
            via: RouteVia::Uplink { interface: 7, .. },
            ..
        })
    ));
    app.acknowledge(p.id(), &[true, true, false], false)
        .unwrap();
    assert!(!app.receive(e, &routes(15, vec![])).unwrap().logical_changed);
    let retry = app.begin_plan(e).unwrap().unwrap();
    assert_eq!(retry.operations().len(), 1);
    ack(&mut app, &retry);
    app.receive(e, &routes(3, vec![])).unwrap();
    let p = app.begin_plan(e).unwrap().unwrap();
    assert_eq!(p.operations().len(), 2);
    ack(&mut app, &p);
    assert_eq!(app.applied(e).len(), 1);
    app.withdraw(e).unwrap();
    let p = app.begin_plan(e).unwrap().unwrap();
    assert_eq!(p.operations().len(), 1);
    ack(&mut app, &p);
    app.forget(e).unwrap();
}

#[test]
fn segmented_256_routes_defer_os_and_reannounce_identically() {
    let l = ProtocolLimits::default();
    let list = (0..=255).map(r).collect::<Vec<_>>();
    let batches = advertisement_batches(&list, 0, l).unwrap();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].records.len(), 255);
    assert_eq!(batches[0].flags, 1);
    assert_eq!(batches[1].flags, 2);
    let mut app = RouteApplications::new(l);
    let e = SessionEpoch::generate().unwrap();
    app.register(e, RouteProfile::Endpoint, None).unwrap();
    app.receive(e, &batches[0]).unwrap();
    assert!(app.begin_plan(e).unwrap().is_none());
    app.receive(e, &batches[1]).unwrap();
    let p = app.begin_plan(e).unwrap().unwrap();
    assert_eq!(p.operations().len(), 256);
    ack(&mut app, &p);
    assert_eq!(advertisement_batches(&list, 0, l).unwrap(), batches);
    for b in &batches {
        app.receive(e, b).unwrap();
    }
    assert!(app.begin_plan(e).unwrap().is_none());
    let before = app.desired(e).unwrap().clone();
    assert!(app
        .receive(
            e,
            &routes(
                3,
                vec![Route {
                    network: [10, 1, 0, 1],
                    netmask: [255, 255, 0, 0]
                }]
            )
        )
        .is_err());
    assert_eq!(app.desired(e), Some(&before));
}

#[test]
fn timers_separate_udp_control_cancel_and_monotonic_time() {
    let mut t = Liveness::new(TimerProfile::Client, 0, 1800).unwrap();
    t.activate(0).unwrap();
    assert!(t.poll(60_000).unwrap().control_keepalive_due);
    t.udp_received(119_999).unwrap();
    assert_eq!(
        t.poll(120_000).unwrap().close,
        Some(CloseReason::ControlTimeout)
    );
    assert_eq!(t.transport_close_deadline(), Some(125_000));
    assert_eq!(t.udp_sent(120_001), Err(ProtocolError::Closed));
    let mut t = Liveness::new(TimerProfile::SiteToSite, 0, 1800).unwrap();
    t.activate(0).unwrap();
    for n in 1..=15 {
        t.control_received(n * 60_000).unwrap();
    }
    assert!(t.poll(900_000).unwrap().rekey_due);
    assert!(t.poll(899_999).is_err());
    t.close(900_000, CloseReason::Cancelled).unwrap();
    let p = t.poll(901_000).unwrap();
    assert!(!p.rekey_due && !p.udp_keepalive_due);
}

#[test]
fn route_query_literal_format_empty_is_not_completion_and_is_bounded() {
    let l = ProtocolLimits::default();
    let enc = ProtocolEncoder::new(l);
    assert_eq!(
        &enc.encode(&ControlMessage::RouteRequest, WireVersion::V4)
            .unwrap()[..],
        &[75, 5, 0, 12, 0]
    );
    assert_eq!(
        &enc.encode(
            &ControlMessage::RouteReply(RouteReply { records: vec![] }),
            WireVersion::V4
        )
        .unwrap()[..],
        &[75, 5, 0, 13, 0]
    );
    let mut q = RouteQuery::new(2);
    q.next_request().unwrap();
    assert!(q.next_request().is_err());
    q.receive(
        &ControlMessage::RouteReply(RouteReply { records: vec![] }),
        l,
    )
    .unwrap();
    assert!(!q.complete());
    q.next_request().unwrap();
    q.receive(
        &ControlMessage::RouteReply(RouteReply { records: vec![] }),
        l,
    )
    .unwrap();
    assert!(q.next_request().is_err());
    let mut q = RouteQuery::new(1);
    q.next_request().unwrap();
    q.receive(&ControlMessage::NoMoreRoutes, l).unwrap();
    assert!(q.complete());
}

#[test]
fn utf8_exact_metadata_boundaries_and_ipv6_capability() {
    let l = ProtocolLimits::default();
    let enc = ProtocolEncoder::new(l);
    let mut encoded = vec![];
    for text in [" é ", " e\u{301} ", "PASSWORD", "password", " пароль "] {
        let m = ControlMessage::Password(Credential::from_utf8(text, l).unwrap());
        let b = enc.encode(&m, WireVersion::V4).unwrap();
        assert_eq!(&b[4..b.len() - 1], text.as_bytes());
        assert_eq!(b[b.len() - 1], 0);
        encoded.push(b);
    }
    assert_ne!(encoded[0], encoded[1]);
    assert_ne!(encoded[2], encoded[3]);
    assert!(Credential::from_utf8("a\0b", l).is_err());
    assert!(Credential::from_utf8(&"x".repeat(130), l).is_ok());
    let description = "я".repeat(63) + "x";
    let metadata = ClientMetadata::new([0, 9, 0], 1, 2, &description).unwrap();
    assert_eq!(metadata.description_bytes(), description.as_bytes());
    assert!(ClientMetadata::new([0, 9, 0], 1, 2, &"я".repeat(64)).is_err());
    assert!(ClientMetadata::new([0, 9, 0], 1, 2, "a\0b").is_err());
    assert!(Capabilities::require_ipv6_configuration().is_err());
}

#[test]
fn legacy_requires_feature_and_runtime_opt_in_and_labels_integrity() {
    for v in [
        WireVersion::V1,
        WireVersion::V2,
        WireVersion::V3,
        WireVersion::V4,
    ] {
        let c = AnyCipherConfig::Legacy(LegacyCipherConfig {
            slot: 0,
            key: LegacyKey::from_bytes([7; 16], [8; 8]),
        });
        let mut disabled = KeySlots::new(v, LegacyPolicy::Disabled).unwrap();
        assert_eq!(
            disabled.install_initial(disabled.epoch(), &c),
            Err(ProtocolError::LegacyDisabled)
        );
        let mut a = KeySlots::new(v, LegacyPolicy::ExplicitlyEnabled).unwrap();
        let ae = a.epoch();
        #[cfg(not(feature = "legacy"))]
        assert_eq!(
            a.install_initial(ae, &c),
            Err(ProtocolError::LegacyDisabled)
        );
        #[cfg(feature = "legacy")]
        {
            a.install_initial(ae, &c).unwrap();
            let mut b = KeySlots::new(v, LegacyPolicy::ExplicitlyEnabled).unwrap();
            let be = b.epoch();
            b.install_initial(be, &c).unwrap();
            let packet = NetworkPacket {
                ether_type: 0x0800,
                payload: Bytes::from_static(b"odd"),
            };
            let raw = a.seal(ae, &packet, ProtocolLimits::default()).unwrap();
            let decoded = b.open(be, raw, ProtocolLimits::default()).unwrap();
            assert_eq!(decoded.packet, packet);
            assert_eq!(
                decoded.integrity,
                if v == WireVersion::V1 {
                    Integrity::NoIntegrity
                } else {
                    Integrity::UnkeyedChecksum
                }
            );
        }
    }
}
