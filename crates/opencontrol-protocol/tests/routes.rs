use bytes::Bytes;
use opencontrol_protocol::{
    crypto::SessionKey,
    datagram::{DataCipher, NetworkPacket},
    *,
};
use proptest::prelude::*;

fn limits() -> ProtocolLimits {
    ProtocolLimits::default()
}
fn route(n: u8) -> Route {
    Route {
        network: [10, n, 0, 0],
        netmask: [255, 255, 0, 0],
    }
}
fn message(flags: u8, records: Vec<Route>) -> Routes {
    Routes { flags, records }
}
fn changed(state: &mut RouteState, message: &Routes) {
    assert!(matches!(
        state.apply(message).unwrap(),
        RouteUpdate::Changed(_)
    ));
}
fn unchanged(state: &mut RouteState, message: &Routes) {
    assert!(matches!(
        state.apply(message).unwrap(),
        RouteUpdate::Unchanged(_)
    ));
}
fn active() -> StateMachine {
    let mut machine = StateMachine::new(Role::Client);
    let mut data = include_bytes!("../../../protocol/vectors/handshake_v4.bin").as_slice();
    while !data.is_empty() {
        let direction = if data[0] == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let frame = ControlFrame {
            opcode: data[1],
            payload: Bytes::copy_from_slice(&data[4..4 + len]),
        };
        let m = ControlMessage::decode(frame, WireVersion::V4, limits()).unwrap();
        machine.observe(direction, &m).unwrap();
        data = &data[4 + len..];
    }
    machine
}

#[test]
fn repeated_replace_and_reordered_duplicates_are_noops() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![route(1), route(2)]));
    unchanged(&mut s, &message(3, vec![route(2), route(1), route(1)]));
    assert_eq!(s.current().unwrap().routes(), [route(1), route(2)]);
    assert!(!s.maintenance_pending());
}
#[test]
fn empty_initial_periodic_replacement_and_clear() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![]));
    unchanged(&mut s, &message(3, vec![]));
    changed(&mut s, &message(3, vec![route(1)]));
    changed(&mut s, &message(3, vec![]));
    assert!(s.current().unwrap().routes().is_empty());
    unchanged(&mut s, &message(3, vec![]));
}
#[test]
fn append_without_replace_and_empty_append_preserves_routes() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![route(1)]));
    changed(&mut s, &message(0, vec![route(2)]));
    unchanged(&mut s, &message(0, vec![route(2)]));
    unchanged(&mut s, &message(2, vec![]));
    assert_eq!(s.current().unwrap().routes(), [route(1), route(2)]);
}
#[test]
fn segmented_replacement_marks_touches_then_sweeps_at_bit1() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![route(1), route(2)]));
    unchanged(&mut s, &message(1, vec![route(1)]));
    assert!(s.maintenance_pending());
    assert_eq!(s.current().unwrap().routes(), [route(1), route(2)]);
    changed(&mut s, &message(0, vec![route(3)]));
    changed(&mut s, &message(2, vec![]));
    assert_eq!(s.current().unwrap().routes(), [route(1), route(3)]);
    assert!(!s.maintenance_pending());
}
#[test]
fn full_tunnel_and_status_only_updates_with_empty_payload() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![]));
    changed(&mut s, &message(11, vec![]));
    assert!(s.current().unwrap().is_full_tunnel());
    assert_eq!(s.current().unwrap().routes().len(), 2);
    unchanged(&mut s, &message(11, vec![]));
    // bit1 alone does not mean "disable full tunnel".
    unchanged(&mut s, &message(2, vec![]));
    changed(&mut s, &message(6, vec![]));
    assert!(s.current().unwrap().safe_lan());
    assert!(s.current().unwrap().is_full_tunnel());
    changed(&mut s, &message(7, vec![]));
    assert!(!s.current().unwrap().is_full_tunnel());
    assert!(s.current().unwrap().safe_lan());
    assert!(s.current().unwrap().routes().is_empty());
}
#[test]
fn unknown_bits_are_preserved_without_invented_changes() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![route(1)]));
    unchanged(&mut s, &message(0xf3, vec![route(1)]));
    assert_eq!(s.last_flags(), Some(0xf3));
    assert_eq!(s.unknown_flags(), 0xf0);
}

#[test]
fn observed_hourly_server_metadata_replays_as_six_noops() {
    // Metadata comes from a real wall-clock run, not raw packet capture. Empty
    // parsed records are sufficient to reconstruct these particular ROUTES values.
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/interop/routes-periodic-hour-20261013.json"
    ))
    .unwrap();
    assert_eq!(evidence["summary"]["passed"], true);
    assert!(evidence["summary"]["elapsed_seconds"].as_f64().unwrap() >= 3600.0);
    let mut state = RouteState::new(limits());
    let initial = &evidence["initial_routes"];
    assert_eq!(initial["count"], 0);
    changed(
        &mut state,
        &message(initial["flags"].as_u64().unwrap() as u8, vec![]),
    );
    let events = evidence["routes"].as_array().unwrap();
    assert_eq!(events.len(), 6);
    for event in events {
        assert_eq!(event["count"], 0);
        assert_eq!(event["changed"], false);
        unchanged(
            &mut state,
            &message(event["flags"].as_u64().unwrap() as u8, vec![]),
        );
    }
}
#[test]
fn invalid_input_is_atomic_including_pending_maintenance() {
    let mut s = RouteState::new(limits());
    changed(&mut s, &message(3, vec![route(1)]));
    unchanged(&mut s, &message(1, vec![]));
    let before = s.current().unwrap().clone();
    let flags = s.last_flags();
    for invalid in [
        message(
            7,
            vec![
                route(2),
                Route {
                    network: [10, 0, 0, 0],
                    netmask: [255, 0, 255, 0],
                },
            ],
        ),
        message(
            3,
            vec![Route {
                network: [10, 0, 0, 1],
                netmask: [255, 255, 255, 0],
            }],
        ),
        message(3, vec![route(2); 256]),
    ] {
        assert!(s.apply(&invalid).is_err());
        assert_eq!(s.current(), Some(&before));
        assert_eq!(s.last_flags(), flags);
        assert!(s.maintenance_pending());
    }
    // Corrupt wire count must still fail the existing decoder, before application.
    assert!(ControlMessage::decode(
        ControlFrame {
            opcode: 19,
            payload: Bytes::from_static(&[3, 1])
        },
        WireVersion::V4,
        limits()
    )
    .is_err());
    assert_eq!(s.current(), Some(&before));
    changed(&mut s, &message(2, vec![]));
    assert!(s.current().unwrap().routes().is_empty());
}
#[test]
fn limits_are_atomic_and_allow_replacement_at_capacity() {
    let mut s = RouteState::new(ProtocolLimits {
        max_collection_items: 1,
        max_route_entries: 1,
        ..limits()
    });
    changed(&mut s, &message(3, vec![route(1)]));
    changed(&mut s, &message(3, vec![route(2)]));
    assert!(s.apply(&message(0, vec![route(3)])).is_err());
    assert_eq!(s.current().unwrap().routes(), [route(2)]);
    let mut small = RouteState::new(ProtocolLimits {
        max_frame_size: 5,
        ..limits()
    });
    assert!(small.apply(&message(3, vec![])).is_err());
    assert!(small.current().is_none());
}
#[test]
fn periodic_updates_at_600_and_1200_seconds_preserve_session_and_both_cipher_slots() {
    let mut machine = active();
    machine
        .outgoing(&ControlMessage::KeyChange(CipherConfig {
            slot: 0,
            key: SessionKey::from_bytes([5; 16]),
        }))
        .unwrap();
    assert_eq!(machine.primary_slot(), Some(1));
    assert_eq!(machine.pending_slot(), Some(0));
    let mut tx = [
        DataCipher::new(SessionKey::from_bytes([5; 16]), 0, WireVersion::V4).unwrap(),
        DataCipher::new(SessionKey::from_bytes([7; 16]), 1, WireVersion::V4).unwrap(),
    ];
    let mut rx = [
        DataCipher::new(SessionKey::from_bytes([5; 16]), 0, WireVersion::V4).unwrap(),
        DataCipher::new(SessionKey::from_bytes([7; 16]), 1, WireVersion::V4).unwrap(),
    ];
    let packet = NetworkPacket {
        ether_type: 0x0800,
        payload: Bytes::from_static(b"data"),
    };
    let first = [
        tx[0].seal(&packet, limits()).unwrap(),
        tx[1].seal(&packet, limits()).unwrap(),
    ];
    for slot in 0..2 {
        rx[slot].open(&first[slot], limits()).unwrap();
    }
    let mut state = RouteState::new(limits());
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/vectors/routes_updates.json"
    ))
    .unwrap();
    for (index, event) in vectors["events"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            event["at_seconds"].as_u64().unwrap(),
            [0, 600, 1200, 1201][index]
        );
        let frame_bytes = hex::decode(event["wire_hex"].as_str().unwrap()).unwrap();
        let mut decoder = ProtocolDecoder::new(limits());
        decoder.push_bytes(&frame_bytes).unwrap();
        let m = ControlMessage::decode(
            decoder.next_frame().unwrap().unwrap(),
            WireVersion::V4,
            limits(),
        )
        .unwrap();
        machine.incoming(&m).unwrap();
        let ControlMessage::Routes(routes) = m else {
            panic!("ROUTES expected")
        };
        if index == 0 {
            changed(&mut state, &routes)
        } else {
            unchanged(&mut state, &routes)
        }
        assert_eq!(machine.state(), ProtocolState::Active);
        assert_eq!(machine.version(), Some(WireVersion::V4));
        assert_eq!(machine.primary_slot(), Some(1));
        assert_eq!(machine.pending_slot(), Some(0));
        for slot in 0..2 {
            assert_eq!(
                rx[slot].open(&first[slot], limits()),
                Err(ProtocolError::Replay)
            );
            let data = tx[slot].seal(&packet, limits()).unwrap();
            assert_eq!(rx[slot].open(&data, limits()).unwrap(), packet);
        }
    }
    // A real configuration change also leaves rekey and crypto untouched.
    let routes = message(11, vec![]);
    machine
        .incoming(&ControlMessage::Routes(routes.clone()))
        .unwrap();
    changed(&mut state, &routes);
    assert_eq!(machine.primary_slot(), Some(1));
    assert_eq!(machine.pending_slot(), Some(0));
    let invalid = message(
        3,
        vec![Route {
            network: [1; 4],
            netmask: [255, 0, 255, 0],
        }],
    );
    let before = state.current().unwrap().clone();
    machine
        .incoming(&ControlMessage::Routes(invalid.clone()))
        .unwrap();
    assert!(state.apply(&invalid).is_err());
    assert_eq!(state.current(), Some(&before));
    assert_eq!(machine.state(), ProtocolState::Active);
    assert_eq!(machine.primary_slot(), Some(1));
    assert_eq!(machine.pending_slot(), Some(0));
    for slot in 0..2 {
        assert_eq!(
            rx[slot].open(&first[slot], limits()),
            Err(ProtocolError::Replay)
        );
    }
    machine
        .incoming(&ControlMessage::KeyChanged(Bytes::from_static(&[0])))
        .unwrap();
    assert_eq!(machine.primary_slot(), Some(0));
    assert_eq!(machine.pending_slot(), None);
}

proptest! {
    #[test]
    fn completed_replacement_is_idempotent_and_order_independent(networks in proptest::collection::vec(any::<u8>(),0..128), flags in any::<u8>()) {
        let mut state = RouteState::new(limits());
        let mut records:Vec<_> = networks.into_iter().map(route).collect();
        let flags = flags | 3;
        prop_assert!(matches!(state.apply(&message(flags,records.clone())).unwrap(),RouteUpdate::Changed(_)));
        let before = state.current().unwrap().clone();
        records.reverse();
        prop_assert!(matches!(state.apply(&message(flags,records)).unwrap(),RouteUpdate::Unchanged(_)));
        prop_assert_eq!(state.current(),Some(&before));
    }
}
