//! Parser tests built from the frame format directly.
//!
//! These are synthetic on purpose. They pin the *framing* — offsets, widths,
//! endianness, alignment — which is the part that is knowable without a radio and the
//! part that, when wrong, makes every later capture look like a protocol mystery.
//!
//! Real captures become fixtures in `captures/` and get their own tests; those pin
//! semantics, which is a different question and needs a real Apple device to answer.

use libawdl::action::{ActionFrame, SUBTYPE_MIF};
use libawdl::dot11::Dot11;
use libawdl::radiotap::Radiotap;
use libawdl::tlv::{Stop, Tlvs};

/// Radiotap carrying TSFT and CHANNEL, which together exercise the 8-byte alignment
/// rule that is the easiest thing to get wrong in this header.
fn radiotap() -> Vec<u8> {
    let mut v = vec![0u8, 0]; // version, pad
    v.extend_from_slice(&20u16.to_le_bytes()); // len
    v.extend_from_slice(&0b1001u32.to_le_bytes()); // present: TSFT | CHANNEL
    v.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // TSFT, 8..16
    v.extend_from_slice(&5745u16.to_le_bytes()); // channel 149
    v.extend_from_slice(&0u16.to_le_bytes()); // channel flags
    assert_eq!(v.len(), 20);
    v
}

fn dot11_action() -> Vec<u8> {
    let mut v = Vec::new();
    // subtype 13 (action) << 4 | type 0 (management) << 2 | version 0
    v.push(0xd0);
    v.push(0x00); // frame control, second byte (flags)
    v.extend_from_slice(&[0x00, 0x00]); // duration
    v.extend_from_slice(&[0x00, 0x25, 0x00, 0xff, 0x94, 0x73]); // dst
    v.extend_from_slice(&[0x6c, 0x8d, 0xc1, 0x11, 0x22, 0x33]); // src
    v.extend_from_slice(&[0x00, 0x25, 0x00, 0xff, 0x94, 0x73]); // bssid
    v.extend_from_slice(&[0x00, 0x00]); // seq
    assert_eq!(v.len(), 24);
    v
}

fn awdl_body(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut v = vec![0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10, SUBTYPE_MIF, 0x00];
    v.extend_from_slice(&1_000u32.to_le_bytes()); // phy tx time
    v.extend_from_slice(&940u32.to_le_bytes()); // target tx time
    for (tag, value) in tlvs {
        v.push(*tag);
        v.extend_from_slice(&(value.len() as u16).to_le_bytes());
        v.extend_from_slice(value);
    }
    v
}

fn frame(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut v = radiotap();
    v.extend_from_slice(&dot11_action());
    v.extend_from_slice(&awdl_body(tlvs));
    v
}

#[test]
fn radiotap_reports_length_tsft_and_frequency() {
    let rt = Radiotap::parse(&radiotap()).expect("radiotap parses");
    assert_eq!(rt.len, 20);
    assert_eq!(rt.tsft, Some(0x1122_3344_5566_7788));
    assert_eq!(rt.freq, Some(5745), "channel 149, the social channel in this region");
}

#[test]
fn a_whole_awdl_frame_comes_apart_correctly() {
    let pkt = frame(&[(4, &[1, 2, 3][..]), (18, &[9; 12][..])]);

    let rt = Radiotap::parse(&pkt).unwrap();
    let body80211 = rt.payload(&pkt).unwrap();

    let d = Dot11::parse(body80211).unwrap();
    assert!(d.is_action());
    assert_eq!(d.src.to_string(), "6c:8d:c1:11:22:33");

    let af = ActionFrame::parse(d.body(body80211).unwrap()).expect("recognised as AWDL");
    assert_eq!((af.fixed.version_major, af.fixed.version_minor), (1, 0), "0x10 is v1.0");
    assert_eq!(af.fixed.subtype, SUBTYPE_MIF);
    assert_eq!(af.fixed.tx_delay(), 60, "1000 - 940");

    let tags: Vec<(u8, usize)> = af.tlvs().map(|t| (t.tag, t.value.len())).collect();
    assert_eq!(tags, vec![(4, 3), (18, 12)]);
}

/// The four checks that separate AWDL from the rest of the air. Each one alone lets
/// other traffic through, so each one is tested by breaking it on its own.
#[test]
fn non_awdl_frames_are_rejected_one_field_at_a_time() {
    let good = awdl_body(&[]);

    let mut wrong_category = good.clone();
    wrong_category[0] = 0x04; // Public Action, not vendor specific
    assert!(ActionFrame::parse(&wrong_category).is_none());

    let mut wrong_oui = good.clone();
    wrong_oui[1..4].copy_from_slice(&[0x00, 0x10, 0x18]); // Broadcom
    assert!(ActionFrame::parse(&wrong_oui).is_none(), "Apple OUI is required");

    let mut wrong_type = good.clone();
    wrong_type[4] = 0x0a; // Apple, but not AWDL
    assert!(
        ActionFrame::parse(&wrong_type).is_none(),
        "the OUI alone is not enough — Apple ships several protocols behind 00:17:f2"
    );

    // A beacon is not an action frame, however Apple-ish its body looks.
    let mut beacon = dot11_action();
    beacon[0] = 0x80;
    assert!(!Dot11::parse(&beacon).unwrap().is_action());
}

#[test]
fn a_tag_running_past_the_end_is_reported_not_trimmed() {
    let mut body = awdl_body(&[]);
    body.push(18); // Channel Sequence
    body.extend_from_slice(&999u16.to_le_bytes()); // claims 999 bytes
    body.extend_from_slice(&[0; 4]); // has 4

    let af = ActionFrame::parse(&body).unwrap();
    let mut it = af.tlvs();
    assert!(it.next().is_none(), "nothing is yielded from a tag we cannot trust");
    assert_eq!(it.stop(), Some(Stop::Overrun { tag: 18, claimed: 999, available: 4 }));
}

#[test]
fn a_clean_tag_region_stops_cleanly() {
    let mut it = Tlvs::new(&[21, 2, 0, 0xaa, 0xbb]);
    assert_eq!(it.next().map(|t| t.tag), Some(21));
    assert!(it.next().is_none());
    assert_eq!(it.stop(), Some(Stop::Clean), "consumed exactly, no trailing bytes");
}

/// The AWDL data header, short form — the payload path.
///
/// Values cross-checked against `tshark -Y awdl_data` on `datapath-wifi-off.pcap`: 44
/// frames, `awdl_data.ethertype` 0x86dd throughout, max `awdl_data.seq` 416.
#[test]
fn the_short_data_header_yields_sequence_and_ethertype() {
    use libawdl::data::{DataHeader, ETHERTYPE_IPV6};

    // 2 unnamed bytes, seq LE, 0x0000 (short form), ethertype BE, then the packet.
    let mut b = vec![0x00, 0x00];
    b.extend_from_slice(&416u16.to_le_bytes());
    b.extend_from_slice(&[0x00, 0x00]);
    b.extend_from_slice(&0x86ddu16.to_be_bytes());
    b.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // start of an IPv6 header

    let h = DataHeader::parse(&b).expect("short form parses");
    assert_eq!(h.sequence, 416);
    assert!(!h.long_form);
    // The ethertype is BIG-endian while the sequence beside it is little-endian. Read
    // 0x86dd the wrong way round and you get 0xdd86, which matches nothing and looks
    // like a framing bug rather than a byte-order one.
    assert_eq!(h.ethertype, ETHERTYPE_IPV6);
    assert_eq!(h.ethertype_name(), "IPv6");
    assert_eq!(h.payload(&b), Some(&[0x60, 0x00, 0x00, 0x00][..]));
}

/// The long form embeds TLVs with a ONE-byte length, not the two-byte form action
/// frames use, and is closed by a second 0x03 marker.
#[test]
fn the_long_data_header_walks_short_tags_and_stops_at_the_marker() {
    use libawdl::data::DataHeader;

    let mut b = vec![0x00, 0x00];
    b.extend_from_slice(&7u16.to_le_bytes()); // seq
    b.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]); // long-form opener: 0x03, len 2
    b.extend_from_slice(&[0x10, 0x02, 0x01, 0x02]); // a short tag: type, len 2, value
    b.extend_from_slice(&[0x03, 0x01, 0xcc]); // closing 0x03 block
    b.extend_from_slice(&0x86ddu16.to_be_bytes());
    b.extend_from_slice(&[0x60]);

    let h = DataHeader::parse(&b).expect("long form parses");
    assert_eq!(h.sequence, 7);
    assert!(h.long_form);
    assert_eq!(h.tagged, &[0x10, 0x02, 0x01, 0x02][..], "one short tag between the markers");
    assert_eq!(h.ethertype, 0x86dd);
}

/// IPv6 multicast is why the data plane is observable at all.
#[test]
fn ipv6_multicast_addresses_are_recognised() {
    use libawdl::data::is_ipv6_multicast;
    // 33:33:00:00:00:fb is ff02::fb, mDNS -- and multicast is never rate-adapted, so
    // these frames arrive at the lowest basic rate and decode when unicast does not.
    assert!(is_ipv6_multicast([0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]));
    assert!(is_ipv6_multicast([0x33, 0x33, 0x00, 0x00, 0x00, 0x16]));
    assert!(!is_ipv6_multicast([0x8a, 0xc3, 0xf7, 0x4b, 0xce, 0xde]));
}
