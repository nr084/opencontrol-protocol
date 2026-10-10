#![no_main]
use libfuzzer_sys::fuzz_target;
use opencontrol_protocol::*;
fuzz_target!(|data: &[u8]| {
    let limits = ProtocolLimits::default();
    let mut decoder = ProtocolDecoder::new(limits);
    for chunk in data.chunks(7) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let Ok(n) = decoder.push_bytes(rest) else {
                return;
            };
            rest = &rest[n..];
            if let Ok(Some(frame)) = decoder.next_frame() {
                for v in [
                    WireVersion::V1,
                    WireVersion::V2,
                    WireVersion::V3,
                    WireVersion::V4,
                ] {
                    if let Ok(m) = ControlMessage::decode(frame.clone(), v, limits) {
                        let encoded = ProtocolEncoder::new(limits).encode(&m, v).unwrap();
                        assert_eq!(
                            encoded,
                            ProtocolEncoder::new(limits).encode_frame(&frame).unwrap()
                        );
                    }
                }
            } else if n == 0 {
                break;
            }
        }
    }
    let _ = decoder.finish();
});
