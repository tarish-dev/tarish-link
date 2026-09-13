//! The data plane, against a frame that really came off a radio.
//!
//! This is an mDNS query from an Apple device to `ff02::fb`, captured on 6 GHz channel 53.
//! Multicast is the only part of the data plane a monitor can read — unicast AirDrop
//! payloads go out at VHT rates the MT7612U cannot demodulate — so this frame is both the
//! evidence for the encapsulation and the only kind of sample available.

use libawdl::data::{
    decapsulate, link_local_from_mac, short_header, Encap, AWDL_BSSID, DATA_HEADER_PREFIX,
    ETHERTYPE_IPV6, QOS_HEADER_LEN, SNAP_AWDL,
};

/// 130 bytes, `captures/6ghz-A-ch53.pcap`. Source `8a:c3:f7:4b:ce:de`, an mDNS A query for
/// `Android_0637B1C2.local` — so the peer on the other side of this was a Pixel.
const REAL_FRAME: &[u8] = &[
    0x88, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0xfb, 0x8a, 0xc3, 0xf7, 0x4b, 0xce, 0xde,
    0x00, 0x25, 0x00, 0xff, 0x94, 0x73, 0x90, 0x67, 0x06, 0x00, 0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2,
    0x08, 0x00, 0x03, 0x04, 0xe3, 0x01, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x05, 0x08, 0x00, 0x00, 0x30,
    0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xc3, 0xf7, 0xff, 0xfe, 0x4b,
    0xce, 0xde, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0x30, 0xc3, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x5f, 0x30,
    0x36, 0x33, 0x37, 0x42, 0x31, 0x43, 0x32, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01,
    0x00, 0x01,
];

#[test]
fn a_real_data_frame_decapsulates() {
    let d = decapsulate(REAL_FRAME).expect("is an AWDL data frame");

    assert_eq!(d.dst, [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb], "IPv6 multicast mapping of ff02::fb");
    assert_eq!(d.src, [0x8a, 0xc3, 0xf7, 0x4b, 0xce, 0xde]);
    assert_eq!(d.header.sequence, 0x01e3);
    assert!(!d.header.long_form, "the long form was never observed in 428 frames");
    assert_eq!(d.header.ethertype, ETHERTYPE_IPV6);

    // The payload is an IPv6 packet and its own header agrees with the frame.
    assert_eq!(d.payload[0] >> 4, 6, "IPv6 version nibble");
    assert_eq!(u16::from_be_bytes([d.payload[4], d.payload[5]]), 48, "payload length");
    assert_eq!(d.payload[6], 17, "next header: UDP");
    assert_eq!(d.payload.len(), 40 + 48, "the 40-byte IPv6 header plus its stated payload");

    // UDP 5353 both ways -- mDNS.
    let udp = &d.payload[40..];
    assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 5353);
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 5353);
}

/// The claim that makes addressing work without any address resolution.
#[test]
fn the_source_address_is_the_eui64_of_the_source_mac() {
    let d = decapsulate(REAL_FRAME).unwrap();
    let ip_src: [u8; 16] = d.payload[8..24].try_into().unwrap();

    assert_eq!(
        link_local_from_mac(d.src),
        ip_src,
        "fe80::88c3:f7ff:fe4b:cede is derived from 8a:c3:f7:4b:ce:de, not advertised"
    );

    // And the part that is easy to get half-right: the flipped bit.
    assert_eq!(ip_src[8], 0x88, "0x8a with bit 1 cleared");
    assert_ne!(ip_src[8], d.src[0], "if these were equal the flip was skipped");
    assert_eq!([ip_src[11], ip_src[12]], [0xff, 0xfe], "inserted in the middle");
}

/// Rebuild the captured frame from its parts and require byte equality.
///
/// This is the test that would catch a wrong constant, because there is nowhere for an
/// error to hide: every byte of a real frame has to come back.
#[test]
fn the_builder_reproduces_a_real_frame_exactly() {
    let d = decapsulate(REAL_FRAME).unwrap();

    // 0x9067 little-endian is sequence control: the low nibble is the fragment number and
    // the top 12 bits the sequence, so 0x6790 >> 4 = 0x679.
    let seq_ctrl = u16::from_le_bytes([REAL_FRAME[22], REAL_FRAME[23]]);
    let dot11_seq = seq_ctrl >> 4;
    assert_eq!(seq_ctrl & 0x0f, 0, "not a fragment");

    let rebuilt = Encap { src: d.src, dst: d.dst, tid: 6 }.frame(
        dot11_seq,
        d.header.sequence,
        d.header.ethertype,
        d.payload,
    );

    assert_eq!(rebuilt.len(), REAL_FRAME.len());
    assert_eq!(rebuilt, REAL_FRAME, "every byte of a real frame, rebuilt from its parts");
}

#[test]
fn the_constants_are_where_the_real_frame_says_they_are() {
    assert_eq!(&REAL_FRAME[16..22], &AWDL_BSSID, "addr3 is the well-known AWDL BSSID");
    assert_eq!(&REAL_FRAME[26..34], &SNAP_AWDL, "Apple's OUI, not 00:00:00");

    // The trap this constant exists to document: a normal SNAP would put the ethertype at
    // offsets 6..8 of itself, which here is 0x0800 -- IPv4. The frame is IPv6.
    assert_eq!(u16::from_be_bytes([SNAP_AWDL[6], SNAP_AWDL[7]]), 0x0800);
    let d = decapsulate(REAL_FRAME).unwrap();
    assert_eq!(d.header.ethertype, ETHERTYPE_IPV6, "and the real ethertype is further on");

    assert_eq!(&REAL_FRAME[34..36], &DATA_HEADER_PREFIX);
    assert_eq!(QOS_HEADER_LEN, 26);
}

/// Not every QoS Data frame is ours. The SNAP is checked, not skipped.
#[test]
fn a_foreign_data_frame_is_refused() {
    let mut other = REAL_FRAME.to_vec();
    // A standard SNAP: same shape, OUI 00:00:00.
    other[26..34].copy_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd]);
    assert!(decapsulate(&other).is_none(), "another vendor's QoS Data is not AWDL's");

    // And a management frame is not a data frame.
    let mut mgmt = REAL_FRAME.to_vec();
    mgmt[0] = 0xd0;
    assert!(decapsulate(&mgmt).is_none());
}

#[test]
fn the_short_header_is_eight_bytes_and_says_so() {
    let h = short_header(0x01e3, ETHERTYPE_IPV6);
    assert_eq!(h, [0x03, 0x04, 0xe3, 0x01, 0x00, 0x00, 0x86, 0xdd]);
    assert_ne!(h[4], 3, "byte 4 == 3 would mark the long form");
}

// ---------------------------------------------------------------------------------------
// Addressing: the part that makes sending possible at all.
// ---------------------------------------------------------------------------------------

use libawdl::data::{dst_mac_for_ipv6, mac_from_link_local, multicast_mac};

/// The real frame gives both directions of the EUI-64 rule at once, which is why it is
/// worth testing against a capture rather than against a hand-built address.
#[test]
fn the_eui64_rule_inverts_on_a_real_frame() {
    let d = decapsulate(REAL_FRAME).unwrap();
    let ip_src: [u8; 16] = d.payload[8..24].try_into().unwrap();

    assert_eq!(mac_from_link_local(ip_src), Some(d.src), "recovered from the address alone");
    assert_eq!(link_local_from_mac(d.src), ip_src, "and back again");
}

/// The captured frame's destination is `ff02::fb` and its destination MAC is
/// `33:33:00:00:00:fb`. The mapping is asserted against those, not against RFC prose.
#[test]
fn multicast_maps_the_way_the_real_frame_does() {
    let d = decapsulate(REAL_FRAME).unwrap();
    let ip_dst: [u8; 16] = d.payload[24..40].try_into().unwrap();

    assert_eq!(ip_dst[0], 0xff, "ff02::fb is multicast");
    assert_eq!(multicast_mac(ip_dst), Some(d.dst));
    assert_eq!(d.dst, [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]);

    // And the whole decision, from the packet alone -- which is what the send path does.
    assert_eq!(dst_mac_for_ipv6(d.payload), Some(d.dst));
}

/// An address that is not EUI-64-derived carries no MAC, and inventing one sends the frame
/// to nobody. A stable-privacy link-local is the case that actually occurs: the kernel adds
/// one to `awdl0` unless `addr_gen_mode` is set to 1 first — finding 51.
#[test]
fn an_address_carrying_no_mac_is_refused_rather_than_guessed() {
    // fe80::66b6:3871:d3dc:2e0d -- the real stable-privacy address the kernel generated.
    let privacy = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x66, 0xb6, 0x38, 0x71, 0xd3, 0xdc, 0x2e, 0x0d,
    ];
    assert_eq!(privacy[0], 0xfe, "it passes the fe80 test");
    assert_eq!(mac_from_link_local(privacy), None, "and fails on the missing ff:fe");

    // A global address is not a link-local at all.
    let global = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(mac_from_link_local(global), None);

    // Non-multicast, non-EUI-64: nothing to send to, and the send path must drop it.
    let mut pkt = vec![0x60, 0, 0, 0, 0, 0, 17, 255];
    pkt.extend_from_slice(&[0u8; 16]);
    pkt.extend_from_slice(&global);
    assert_eq!(pkt.len(), 40);
    assert_eq!(dst_mac_for_ipv6(&pkt), None);
}

#[test]
fn a_truncated_or_non_ipv6_packet_is_not_addressed() {
    assert_eq!(dst_mac_for_ipv6(&[0x60, 0, 0]), None, "shorter than a v6 header");
    let mut v4 = vec![0x45u8; 40];
    v4[0] = 0x45;
    assert_eq!(dst_mac_for_ipv6(&v4), None, "IPv4 -- and no AWDL frame has ever carried it");
}
