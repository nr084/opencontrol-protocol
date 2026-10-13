//! Long-lived control consumer with virtual time. No sockets, TUN or OS operations.
use bytes::Bytes;
use opencontrol_protocol::*;

/// The real platform applies only the configuration/status that actually changed.
trait Platform {
    fn update_routes(&mut self, configuration: &RouteConfiguration) -> Result<(), ProtocolError>;
}
#[derive(Default)]
struct RecordingPlatform {
    updates: usize,
}
impl Platform for RecordingPlatform {
    fn update_routes(&mut self, _: &RouteConfiguration) -> Result<(), ProtocolError> {
        self.updates += 1;
        Ok(())
    }
}
fn handle_control(
    machine: &mut StateMachine,
    route_state: &mut RouteState,
    message: &ControlMessage,
    platform: &mut impl Platform,
) -> Result<(), ProtocolError> {
    machine.incoming(message)?; // Omit this if the transport already observes incoming messages.
    if let ControlMessage::Routes(routes) = message {
        // Commit after platform success, so a failed OS update can be retried.
        let mut candidate = route_state.clone();
        match candidate.apply(routes)? {
            RouteUpdate::Unchanged(_) => (),
            RouteUpdate::Changed(configuration) => platform.update_routes(configuration)?,
        }
        *route_state = candidate;
    }
    Ok(())
}
fn ready_client() -> Result<StateMachine, ProtocolError> {
    // Synthetic developer transcript, not a network connection.
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
        machine.observe(
            direction,
            &ControlMessage::decode(frame, WireVersion::V4, ProtocolLimits::default())?,
        )?;
        data = &data[4 + len..];
    }
    Ok(machine)
}
fn main() -> Result<(), ProtocolError> {
    let mut machine = ready_client()?;
    machine.outgoing(&ControlMessage::KeyChange(CipherConfig {
        slot: 0,
        key: crypto::SessionKey::generate()?,
    }))?;
    let mut route_state = RouteState::new(ProtocolLimits::default());
    let mut platform = RecordingPlatform::default();
    let periodic = ControlMessage::Routes(Routes {
        flags: 3,
        records: vec![],
    });
    for at_seconds in [0, 600, 1200, 1201] {
        handle_control(&mut machine, &mut route_state, &periodic, &mut platform)?;
        assert_eq!(machine.state(), ProtocolState::Active);
        assert_eq!(machine.primary_slot(), Some(1));
        assert_eq!(machine.pending_slot(), Some(0));
        assert_eq!(platform.updates, 1);
        println!(
            "virtual t={at_seconds}s: Active, platform_updates={}",
            platform.updates
        );
    }
    handle_control(
        &mut machine,
        &mut route_state,
        &ControlMessage::Routes(Routes {
            flags: 11,
            records: vec![],
        }),
        &mut platform,
    )?;
    assert!(route_state
        .current()
        .is_some_and(RouteConfiguration::is_full_tunnel));
    assert_eq!(platform.updates, 2);
    println!("real route change delivered; simulation only, no live-server test");
    Ok(())
}
#[test]
fn long_lived_consumer_keeps_periodic_routes_nonterminal() {
    main().unwrap();
}

#[test]
fn failed_platform_update_can_be_retried_without_committing_tracker() {
    struct FailingPlatform;
    impl Platform for FailingPlatform {
        fn update_routes(&mut self, _: &RouteConfiguration) -> Result<(), ProtocolError> {
            Err(ProtocolError::InvalidField("example platform failure"))
        }
    }
    let mut machine = ready_client().unwrap();
    let mut state = RouteState::new(ProtocolLimits::default());
    let routes = ControlMessage::Routes(Routes {
        flags: 11,
        records: vec![],
    });
    assert!(handle_control(&mut machine, &mut state, &routes, &mut FailingPlatform).is_err());
    assert!(state.current().is_none());
    assert_eq!(machine.state(), ProtocolState::Active);
    let mut platform = RecordingPlatform::default();
    handle_control(&mut machine, &mut state, &routes, &mut platform).unwrap();
    assert_eq!(platform.updates, 1);
    assert!(state.current().unwrap().is_full_tunnel());
}
