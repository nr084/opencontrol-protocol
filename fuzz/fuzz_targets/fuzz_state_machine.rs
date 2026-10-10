#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opencontrol_protocol::*;
fuzz_target!(|data: &[u8]| {
    let mut machine = StateMachine::new(Role::Server);
    let limits = ProtocolLimits::default();
    let mut data = data;
    // Records: direction:u8, opcode:u8, payload_length:u16le, payload.
    // Variable lengths let a seeded transcript reach configuration and active states.
    while data.len() >= 4 {
        let length = u16::from_le_bytes([data[2], data[3]]) as usize;
        if length > data.len() - 4 {
            break;
        }
        let event = &data[..4 + length];
        data = &data[4 + length..];
        let frame = ControlFrame {
            opcode: event[1],
            payload: Bytes::copy_from_slice(&event[4..]),
        };
        if let Ok(m) =
            ControlMessage::decode(frame, machine.version().unwrap_or(WireVersion::V4), limits)
        {
            let before = machine.state();
            if machine
                .observe(
                    if event[0] & 1 == 0 {
                        Direction::ClientToServer
                    } else {
                        Direction::ServerToClient
                    },
                    &m,
                )
                .is_err()
            {
                assert_eq!(machine.state(), before);
            }
        }
    }
});
