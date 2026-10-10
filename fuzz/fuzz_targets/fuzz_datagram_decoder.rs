#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opencontrol_protocol::{datagram::Datagram, ProtocolLimits};
fuzz_target!(|data: &[u8]| {
    let limits = ProtocolLimits::default();
    if let Ok(d) = Datagram::decode(Bytes::copy_from_slice(data), limits) {
        assert_eq!(d.encode(limits).unwrap().as_ref(), data);
    }
});
