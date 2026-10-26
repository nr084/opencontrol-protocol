#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opencontrol_protocol::{
    connection::*, route_application::*, routes::RouteProfile, s2s::*, session::*, *,
};
fuzz_target!(|data: &[u8]| {
    let l = ProtocolLimits {
        max_route_entries: 64,
        ..ProtocolLimits::default()
    };
    for profile in [
        SessionProfile::ClientServer(Role::Client),
        SessionProfile::ClientServer(Role::Server),
        SessionProfile::SiteToSite(EndpointRole::Acceptor),
        SessionProfile::SiteToSite(EndpointRole::Initiator),
    ] {
        let mut s = ProtocolSession::new(
            profile,
            WireVersion::V4,
            l,
            LegacyPolicy::ExplicitlyEnabled,
            0,
            60,
        )
        .unwrap();
        let e = s.epoch();
        for (i, chunk) in data.chunks(32).take(128).enumerate() {
            if let Some((&opcode, payload)) = chunk.split_first() {
                if let Ok(m) = ControlMessage::decode(
                    ControlFrame {
                        opcode,
                        payload: Bytes::copy_from_slice(payload),
                    },
                    WireVersion::V4,
                    l,
                ) {
                    let _ = s.observe(
                        e,
                        if i % 2 == 0 {
                            Flow::Incoming
                        } else {
                            Flow::Outgoing
                        },
                        &m,
                        i as u64,
                    );
                }
            }
        }
        let _ = s.reconnect(128);
        let _ = s.poll(e, 129);
    }
    let mut slots = KeySlots::new(WireVersion::V4, LegacyPolicy::ExplicitlyEnabled).unwrap();
    let e = slots.epoch();
    let _ = slots.install_initial(
        e,
        &AnyCipherConfig::Legacy(LegacyCipherConfig {
            slot: 0,
            key: LegacyKey::from_bytes([0; 16], [0; 8]),
        }),
    );
    let _ = slots.open(e, Bytes::copy_from_slice(data), l);
    let mut a = RouteApplications::new(l);
    let owner = SessionEpoch::generate().unwrap();
    a.register(owner, RouteProfile::Endpoint, None).unwrap();
    for chunk in data.chunks(10).take(128) {
        if chunk.len() >= 9 {
            let mut net = [0; 4];
            net.copy_from_slice(&chunk[1..5]);
            let mut mask = [0; 4];
            mask.copy_from_slice(&chunk[5..9]);
            let _ = a.receive(
                owner,
                &Routes {
                    flags: chunk[0],
                    records: vec![Route {
                        network: net,
                        netmask: mask,
                    }],
                },
            );
        }
        if let Ok(Some(p)) = a.begin_plan(owner) {
            let _ = a.acknowledge(p.id(), &vec![false; p.operations().len()], false);
        }
    }
});
