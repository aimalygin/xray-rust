use super::*;

const ID: [u8; TRANSACTION_ID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

#[test]
fn request_is_the_bare_header() {
    let request = binding_request(ID);
    assert_eq!(&request[..8], &[0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42]);
    assert_eq!(&request[8..], &ID);
}

#[test]
fn reads_xor_mapped_addresses_of_both_families() {
    for mapped in ["203.0.113.7:40000", "[2001:db8::7]:5000"] {
        let mapped: SocketAddr = mapped.parse().unwrap();
        let response = binding_success(ID, mapped);
        assert_eq!(
            parse_binding_response(&response),
            Some(BindingResponse {
                transaction_id: ID,
                mapped
            })
        );
    }
}

#[test]
fn refuses_what_pion_refuses() {
    let good = binding_success(ID, "203.0.113.7:40000".parse().unwrap());
    let mut cookie = good.clone();
    cookie[4] ^= 1;
    assert!(parse_binding_response(&cookie).is_none());
    // A Binding request is no success.
    let mut request = good.clone();
    request[1] = 0x01;
    request[0] = 0x00;
    assert!(parse_binding_response(&request).is_none());
    // The two bits above the type are dropped.
    let mut high = good.clone();
    high[0] |= 0xC0;
    assert!(parse_binding_response(&high).is_some());
    // A length the buffer does not hold.
    assert!(parse_binding_response(&good[..good.len() - 1]).is_none());
    // Trailing bytes are ignored.
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0; 7]);
    assert!(parse_binding_response(&trailing).is_some());
}
