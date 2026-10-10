use opencontrol_protocol::Routes;
use opencontrol_protocol::{BindingSecret, IpConfig};

#[test]
fn client_dns_sentinel_policy_does_not_mutate_wire_fields() {
    let config = IpConfig {
        address: [10, 189, 141, 2],
        netmask: [255, 255, 255, 0],
        cep: 1800,
        dns: [[127, 0, 0, 1], [0; 4]],
        extended: None,
        flags: Some(0),
        secret: BindingSecret([0; 128]),
    };
    assert_eq!(config.client_dns_servers(), [[10, 189, 141, 1]]);
    assert_eq!(config.dns[0], [127, 0, 0, 1]);
    let config = IpConfig {
        dns: [[1, 1, 1, 1], [8, 8, 8, 8]],
        ..config
    };
    assert_eq!(config.client_dns_servers(), [[1, 1, 1, 1], [8, 8, 8, 8]]);
}

#[test]
fn observed_route_flags_keep_unknown_bits_opaque() {
    for flags in 0..=255 {
        let routes = Routes {
            flags,
            records: vec![],
        };
        assert_eq!(routes.replaces_routes(), flags & 1 != 0);
        assert_eq!(routes.is_full_tunnel(), flags & 9 == 9);
    }
    assert!(!Routes {
        flags: 1,
        records: vec![]
    }
    .is_full_tunnel());
    assert!(Routes {
        flags: 9,
        records: vec![]
    }
    .is_full_tunnel());
}
