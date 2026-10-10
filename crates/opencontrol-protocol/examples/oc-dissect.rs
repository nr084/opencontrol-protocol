//! Payload-redacted developer tool; parser logic stays in the library.
use opencontrol_protocol::*;
use std::{fs::File, io::Read};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: oc-dissect stream.bin wire-version")?;
    let version = WireVersion::try_from(args.next().ok_or("missing wire version")?.parse::<u8>()?)?;
    let mut file = File::open(path)?;
    let limits = ProtocolLimits::default();
    let mut decoder = ProtocolDecoder::new(limits);
    let mut state = StateMachine::new(Role::Server);
    let mut input = [0; 4096];
    loop {
        let count = file.read(&mut input)?;
        if count == 0 {
            break;
        }
        let mut rest = &input[..count];
        while !rest.is_empty() {
            let consumed = decoder.push_bytes(rest)?;
            rest = &rest[consumed..];
            if let Some(frame) = decoder.next_frame()? {
                let opcode = frame.opcode;
                let length = frame.payload.len() + 4;
                let message = ControlMessage::decode(frame, version, limits)?;
                let accepted = state.incoming(&message).is_ok();
                println!("direction=C->S opcode={opcode} length={length} state={:?} order_accepted={accepted}",state.state());
            }
        }
    }
    decoder.finish()?;
    Ok(())
}
