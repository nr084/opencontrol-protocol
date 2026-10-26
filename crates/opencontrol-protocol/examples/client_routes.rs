//! Virtual-time consumer. The mock OS acknowledges actual operations, including failures.
use bytes::Bytes;
use opencontrol_protocol::{route_application::*, routes::RouteProfile, session::SessionEpoch, *};
#[derive(Default)]
struct Platform {
    operations: usize,
    fail_next: bool,
}
impl Platform {
    fn apply(&mut self, _: &RouteOperation) -> bool {
        if self.fail_next {
            self.fail_next = false;
            false
        } else {
            self.operations += 1;
            true
        }
    }
}
fn reconcile(
    app: &mut RouteApplications,
    e: SessionEpoch,
    p: &mut Platform,
) -> Result<(), ProtocolError> {
    if let Some(plan) = app.begin_plan(e)? {
        let mut success = vec![false; plan.operations().len()];
        for (i, op) in plan.operations().iter().enumerate() {
            success[i] = p.apply(op);
            if !success[i] {
                break;
            }
        }
        app.acknowledge(plan.id(), &success, true)?;
    }
    Ok(())
}
fn ready_client() -> Result<StateMachine, ProtocolError> {
    let mut machine = StateMachine::new(Role::Client);
    let mut data = include_bytes!("../../../protocol/vectors/handshake_v4.bin").as_slice();
    while !data.is_empty() {
        let direction = if data[0] == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let m = ControlMessage::decode(
            ControlFrame {
                opcode: data[1],
                payload: Bytes::copy_from_slice(&data[4..4 + len]),
            },
            WireVersion::V4,
            ProtocolLimits::default(),
        )?;
        machine.observe(direction, &m)?;
        data = &data[4 + len..];
    }
    Ok(machine)
}
fn main() -> Result<(), ProtocolError> {
    let mut machine = ready_client()?;
    let e = SessionEpoch::generate()?;
    let mut app = RouteApplications::new(ProtocolLimits::default());
    app.register(
        e,
        RouteProfile::Client,
        Some(EndpointBypass {
            address: [192, 0, 2, 1],
            gateway: Some([192, 0, 2, 254]),
            uplink: 1,
        }),
    )?;
    let mut platform = Platform::default();
    let periodic = Routes {
        flags: 3,
        records: vec![],
    };
    for seconds in [0, 600, 1200] {
        machine.incoming_event(&ControlMessage::Routes(periodic.clone()))?;
        let notice = app.receive(e, &periodic)?;
        reconcile(&mut app, e, &mut platform)?;
        assert_eq!(machine.state(), ProtocolState::Active);
        assert_eq!(platform.operations, 0);
        println!(
            "virtual t={seconds}: Active, logical_changed={}",
            notice.logical_changed
        );
    }
    // Full tunnel: preserve endpoint first. A partial OS failure does not discard wire state.
    app.receive(
        e,
        &Routes {
            flags: 15,
            records: vec![],
        },
    )?;
    platform.fail_next = true;
    reconcile(&mut app, e, &mut platform)?;
    assert!(app.applied(e).is_empty());
    assert!(
        !app.receive(
            e,
            &Routes {
                flags: 15,
                records: vec![]
            }
        )?
        .logical_changed
    );
    reconcile(&mut app, e, &mut platform)?;
    assert_eq!(app.applied(e).len(), 3);
    app.receive(
        e,
        &Routes {
            flags: 3,
            records: vec![],
        },
    )?;
    reconcile(&mut app, e, &mut platform)?;
    assert_eq!(app.applied(e).len(), 1); // endpoint /32 retained until cleanup
    app.withdraw(e)?;
    reconcile(&mut app, e, &mut platform)?;
    app.forget(e)?;
    println!("mock OS retry and owned cleanup passed; no live connection or OS changes");
    Ok(())
}
#[test]
fn long_lived_consumer_and_os_retry() {
    main().unwrap();
}
