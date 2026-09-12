//! The parser against a frame that actually came off a radio.
//!
//! The synthetic tests in `parse.rs` pin the framing. This one pins the parser against
//! hardware, which catches a different class of mistake: a field that is right in
//! theory and wrong in the air, and a radiotap header shaped the way a real driver
//! shapes it rather than the way the spec's example does.
//!
//! Every expected value below was independently confirmed with `tshark -Y awdl` on the
//! same capture, so this asserts agreement with Wireshark, not merely self-consistency.

mod fixture_frame;

use libawdl::action::{ActionFrame, SUBTYPE_MIF};
use libawdl::dot11::{Dot11, FrameControl};
use libawdl::radiotap::Radiotap;

#[test]
fn a_real_frame_from_a_real_apple_device_parses() {
    let pkt = fixture_frame::FRAME;

    let rt = Radiotap::parse(pkt).expect("radiotap from a live mt76 capture");
    assert_eq!(rt.freq, Some(5745), "captured on channel 149");
    assert!(rt.signal_dbm.is_some_and(|s| s < 0), "a real signal is negative dBm");

    let body80211 = rt.payload(pkt).unwrap();
    assert!(FrameControl::parse(body80211).unwrap().is_action());

    let d = Dot11::parse(body80211).unwrap();
    let af = ActionFrame::parse(d.body(body80211).unwrap()).expect("is AWDL");

    assert_eq!(af.fixed.subtype, SUBTYPE_MIF, "a Master Indication Frame");

    // AWDL SENDERS USE RANDOMISED MAC ADDRESSES. Every sender in this capture has the
    // locally-administered bit set, which is worth asserting: anything keyed on a
    // stable hardware address will work on a bench and fail in the field.
    assert_eq!(d.src.0[0] & 0x02, 0x02, "locally administered (randomised) address");

    // The tag region has to consume exactly, with nothing left over.
    let mut tlvs = af.tlvs();
    let tags: Vec<u8> = tlvs.by_ref().map(|t| t.tag).collect();
    assert_eq!(tlvs.stop(), Some(libawdl::tlv::Stop::Clean), "tags consume the region exactly");

    for required in [4u8, 5, 6, 18, 21] {
        assert!(
            tags.contains(&required),
            "a MIF carries tag {required} ({})",
            libawdl::tlv::tag_name(required)
        );
    }
}

/// Tags 32 and 33 are on the wire and are in no published table.
///
/// Wireshark's own enum stops at 24 (Election Parameters v2), yet both appear 184 times
/// each in a 45-second capture — confirmed by `tshark -e awdl.tag.number`, so this is
/// not our parser inventing them. Recorded as a test so that if a future change starts
/// silently dropping unknown tags, this fails instead of the finding quietly vanishing.
#[test]
fn undocumented_tags_are_preserved_not_discarded() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let body80211 = rt.payload(pkt).unwrap();
    let d = Dot11::parse(body80211).unwrap();
    let af = ActionFrame::parse(d.body(body80211).unwrap()).unwrap();

    let unknown: Vec<u8> = af.tlvs().map(|t| t.tag).filter(|t| *t > 24).collect();
    assert!(
        !unknown.is_empty(),
        "this capture carries tags beyond the published set; if that stops being true, \
         say so deliberately rather than deleting the test"
    );
    for t in unknown {
        assert_eq!(libawdl::tlv::tag_name(t), "unrecognised");
    }
}

/// The timing claims from the 2018 paper, checked against a 2026 device.
///
/// The paper is eight years old and its claims are assumptions until a capture says
/// otherwise. These two hold. Cross-checked with `tshark -V`: `Availability Window
/// Period: 16 TU` in all 278 frames of the capture, and `Number of Channels (+1): 15`.
#[test]
fn availability_window_and_sequence_length_match_the_paper() {
    let sp = sync_params();
    assert_eq!(sp.aw_period, 16, "16 TU, as Stute et al. describe");
    assert_eq!(sp.aw_period_us(), 16_384, "1 TU is 1024 us, not 1000");

    let seq = sp.channel_sequence.as_ref().expect("tag 4 embeds its own sequence");
    assert_eq!(seq.channels.len(), 16, "16 slots");
}

/// One frame describes its schedule TWICE, in two different encodings.
///
/// Tag 4 embeds a `Legacy` sequence; tag 18 carries an `OpClass` one for the same
/// frame. They are not copies: where Legacy says 151, OpClass says 149 or 153 — the
/// 40 MHz centre against the 20 MHz control channel. Reading only one gives a
/// self-consistent and incomplete picture of where the peer actually listens.
#[test]
fn the_two_channel_sequences_agree_on_occupancy_and_differ_on_channel() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let b = rt.payload(pkt).unwrap();
    let d = Dot11::parse(b).unwrap();
    let af = ActionFrame::parse(d.body(b).unwrap()).unwrap();

    let embedded = sync_params().channel_sequence.expect("tag 4 sequence");
    let standalone = af
        .tlvs()
        .find(|t| t.tag == 18)
        .and_then(|t| libawdl::sync::ChannelSequence::parse(t.value))
        .expect("tag 18 sequence");

    assert_eq!(embedded.encoding, libawdl::sync::ChanEncoding::Legacy);
    assert_eq!(standalone.encoding, libawdl::sync::ChanEncoding::OpClass);

    // Same schedule: the node is present in the same windows either way.
    assert_eq!(
        embedded.occupied_slots(),
        standalone.occupied_slots(),
        "both sequences describe the same windows"
    );
}

/// A device is absent for most of its own schedule.
///
/// Occupancy across the capture ran from 3/16 to 9/16 slots. That is the number that
/// decides whether two peers can talk: they need windows where both are present AND on
/// the same channel, so a node at 3/16 sets a hard ceiling on any peer's throughput
/// regardless of link rate.
#[test]
fn most_slots_are_empty_and_that_is_normal() {
    let seq = sync_params().channel_sequence.expect("tag 4 sequence");
    let occupied = seq.occupied_slots();
    assert!(occupied > 0, "a node present in no window at all would be undiscoverable");
    assert!(
        occupied < seq.channels.len(),
        "empty slots are the norm, not a parse failure — observed 3/16 to 9/16"
    );
    assert!(!seq.distinct().contains(&0), "channel 0 means absent, not a channel");
}

fn sync_params() -> libawdl::sync::SyncParams {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let b = rt.payload(pkt).unwrap();
    let d = Dot11::parse(b).unwrap();
    let af = ActionFrame::parse(d.body(b).unwrap()).unwrap();
    af.tlvs()
        .find(|t| t.tag == 4)
        .and_then(|t| libawdl::sync::SyncParams::parse(t.value))
        .expect("every frame in the capture carries tag 4")
}

/// Election fields from a real Apple device.
///
/// Values cross-checked with `tshark -V` on the same capture: `Self Metric: 510`,
/// `Distance to Master: 0`, and a `Self Counter` in the 68192-68194 range that
/// increments across frames.
#[test]
fn election_parameters_decode_and_the_counter_is_live() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let b = rt.payload(pkt).unwrap();
    let d = Dot11::parse(b).unwrap();
    let af = ActionFrame::parse(d.body(b).unwrap()).unwrap();

    let v1 = af
        .tlvs()
        .find(|t| t.tag == 5)
        .and_then(|t| libawdl::election::ElectionParams::parse(t.value))
        .expect("tag 5 present in every frame observed");

    let v2 = af
        .tlvs()
        .find(|t| t.tag == 24)
        .and_then(|t| libawdl::election::ElectionParamsV2::parse(t.value))
        .expect("tag 24 present alongside tag 5, not instead of it");

    // BOTH tags in one frame. A device advertises v1 and v2 simultaneously, so an
    // implementation that emits only one is not doing what the devices do.
    assert!(v1.self_metric > 0, "a real node advertises a real metric");
    assert!(v2.self_metric > 0);

    // The counter is the first term in the election ordering, and on a live device it
    // is a large moving number rather than a placeholder. Our own stack advertises 0
    // here -- see FINDINGS.md 9.
    assert!(
        v2.self_counter > 1000,
        "a live master counter is a long-running value, not a small constant"
    );

    // v1 and v2 must agree about who the master is, or the two advertisements are
    // telling peers different stories.
    assert_eq!(v1.master, v2.master, "v1 and v2 name the same master");
}

/// Service records decode to names a person would recognise.
///
/// Counts cross-checked against `tshark -V` on `two-locks-awdl.pcap`: 444
/// `_airdrop._tcp.local`, 246 each of `_appsvcprepair` and
/// `_applicationservicepairing`, and port 8770 on all 444 AirDrop SRVs.
#[test]
fn service_records_carry_the_airdrop_service_and_its_port() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let b = rt.payload(pkt).unwrap();
    let d = Dot11::parse(b).unwrap();
    let af = ActionFrame::parse(d.body(b).unwrap()).unwrap();

    let mut all = Vec::new();
    for t in af.tlvs().filter(|t| t.tag == 2) {
        all.extend(libawdl::service::records(t.value));
    }
    assert!(!all.is_empty(), "tag 2 is the densest tag in the protocol");

    // The dictionary is the whole point: _airdrop._tcp.local is two bytes on the wire,
    // so a decoder that does not know 0xC007 produces names that still parse and are
    // wrong.
    assert!(
        all.iter().any(|r| r.name().contains("_airdrop") || matches!(
            r, libawdl::service::Record::Ptr { target, .. } if target.contains("_airdrop")
        )),
        "the compressed label 0xC007 must expand to _airdrop._tcp.local"
    );
}

/// AirDrop's port is 8770, read off the air rather than assumed.
#[test]
fn srv_records_are_big_endian_and_give_port_8770() {
    let pkt = fixture_frame::FRAME;
    let rt = Radiotap::parse(pkt).unwrap();
    let b = rt.payload(pkt).unwrap();
    let d = Dot11::parse(b).unwrap();
    let af = ActionFrame::parse(d.body(b).unwrap()).unwrap();

    let ports: Vec<u16> = af
        .tlvs()
        .filter(|t| t.tag == 2)
        .flat_map(|t| libawdl::service::records(t.value))
        .filter_map(|r| match r {
            libawdl::service::Record::Srv { port, name, .. } if name.contains("_airdrop") => {
                Some(port)
            }
            _ => None,
        })
        .collect();

    if !ports.is_empty() {
        // SRV priority/weight/port are big-endian, unlike every other AWDL field.
        // Read little-endian, 8770 becomes 16418 -- a plausible-looking wrong answer.
        assert!(ports.iter().all(|p| *p == 8770), "AirDrop listens on 8770, got {ports:?}");
    }
}

/// The dictionary, checked at its edges.
#[test]
fn compressed_labels_expand_and_null_contributes_nothing() {
    use libawdl::service::{compressed_label, decode_name};
    assert_eq!(compressed_label(0xC007), Some("_airdrop._tcp.local"));
    assert_eq!(compressed_label(0xC00C), Some("local"));
    // 0xC000 is structurally a label but adds no text, so it must not leave an empty
    // component behind -- that would render as a stray dot.
    assert_eq!(compressed_label(0xC000), None);

    // A regular label followed by a dictionary code, which is the common shape.
    let buf = [0x04, b't', b'e', b's', b't', 0xC0, 0x0C];
    let (name, used) = decode_name(&buf, buf.len()).unwrap();
    assert_eq!(name, "test.local");
    assert_eq!(used, buf.len());
}

/// Data Path State names the access point's channel — independently of slot 0.
///
/// Cross-checked with `tshark -V` on `assoc-connected.pcap`: `Infrastructure Channel: 104`
/// in 166 frames and `0` in 165, with `Infrastructure BSSID: 00:00:00:00:00:00` in all 331.
#[test]
fn data_path_state_discloses_the_ap_channel_but_zeroes_its_bssid() {
    use libawdl::state::{flag, DataPathState};

    // flags: INFRA_BSSID | INFRA_ADDRESS, then BSSID(6) + channel(2), then address(6).
    let mut v = Vec::new();
    v.extend_from_slice(&(flag::INFRA_BSSID | flag::INFRA_ADDRESS).to_le_bytes());
    v.extend_from_slice(&[0u8; 6]); // BSSID, zeroed as Apple sends it
    v.extend_from_slice(&104u16.to_le_bytes());
    v.extend_from_slice(&[0x2a, 0xf3, 0x94, 0x4d, 0x96, 0x79]);

    let s = DataPathState::parse(&v).expect("parses");
    assert!(s.is_associated(), "the INFRA_BSSID bit is itself the association signal");
    assert_eq!(s.infra_channel, Some(104));
    assert_eq!(
        s.infra_bssid,
        Some([0u8; 6]),
        "Apple zeroes the BSSID -- the channel is disclosed because a peer needs it for \
         scheduling, the network identity is not"
    );
    assert_eq!(s.infra_address, Some([0x2a, 0xf3, 0x94, 0x4d, 0x96, 0x79]));
}

/// Field order in Data Path State is NOT bit order.
///
/// Country (0x0100) and social channel (0x0200) precede the infrastructure fields
/// (0x0001, 0x0002) on the wire. Walking the bits numerically reads everything after the
/// first set bit from the wrong offset — and produces plausible values, not an error.
#[test]
fn data_path_state_field_order_is_not_bit_order() {
    use libawdl::state::{flag, DataPathState};

    let mut v = Vec::new();
    v.extend_from_slice(&(flag::COUNTRY | flag::INFRA_BSSID).to_le_bytes());
    v.extend_from_slice(b"QA\0"); // country comes FIRST despite its higher bit
    v.extend_from_slice(&[0u8; 6]);
    v.extend_from_slice(&149u16.to_le_bytes());

    let s = DataPathState::parse(&v).unwrap();
    assert_eq!(s.country.as_deref(), Some("QA"));
    assert_eq!(
        s.infra_channel,
        Some(149),
        "if the country block were read after the infra block, this would be 0x0000 or junk"
    );
}

/// Version and Arpa, the two small tags.
#[test]
fn version_packs_nibbles_and_arpa_carries_the_host_name() {
    use libawdl::state::{Arpa, Version};

    let v = Version::parse(&[0x10, 0x02]).expect("parses");
    assert_eq!((v.major, v.minor), (1, 0), "0x10 is 1.0, not 16");
    assert_eq!(v.class_name(), "iOS");

    // flags byte, then a compressed name ending at the `local` dictionary code.
    let mut a = vec![0x00, 0x07];
    a.extend_from_slice(b"tarish1");
    a.extend_from_slice(&[0xC0, 0x0C]);
    let arpa = Arpa::parse(&a).expect("parses");
    assert_eq!(arpa.name, "tarish1.local");
}

/// Tags 32 and 33 carry 6 GHz channels — decoded from captures, not from any published
/// table.
///
/// Wireshark's tag enumeration ends at 24 and reports both unnamed. The reading rests on
/// three things: the class byte is always 0x86 = 134, which is 802.11's operating class for
/// 6 GHz at 160 MHz; the channel byte takes only 53, 85 and 17, all valid 6 GHz channels;
/// and 53 is exactly what the Mac in these captures reports for itself
/// (`Channel: 53 (6GHz, 160MHz)`).
#[test]
fn the_undocumented_tags_carry_six_gigahertz_channels() {
    use libawdl::state::{SixGhzChannels, SixGhzInfo};

    // A verbatim tag 32 value from captures/assoc-connected.pcap.
    let t32 = [0x00, 0x00, 0x86, 0x00, 0x35, 0x00, 0x04, 0x08, 0x02, 0x83, 0x8a, 0x00, 0x00];
    let i = SixGhzInfo::parse(&t32).expect("13 bytes, parses");
    assert_eq!(i.channel.channel, 53);
    assert_eq!(i.channel.opclass, 134);
    assert_eq!(i.channel.band(), "6 GHz");
    assert!(i.channel.is_6ghz());

    // A verbatim tag 33 value from the same capture.
    let t33 = [
        0x01, 0x00, 0x00, 0x00, 0x35, 0x86, 0x01, 0x35, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let c = SixGhzChannels::parse(&t33).expect("14 bytes, parses");
    // CHANNEL FIRST here, class second -- the opposite order to tag 32, and the same as
    // the channel sequence's OpClass form. Swapped, 0x86 reads as channel 134 and 0x35 as
    // class 53, which is a plausible channel number in the wrong band.
    assert_eq!(c.first.map(|p| (p.channel, p.opclass)), Some((53, 134)));
    assert_eq!(c.second.map(|p| (p.channel, p.opclass)), Some((53, 134)));
    assert_eq!(
        c.first, c.second,
        "both pairs have been identical in every capture — one channel stated twice"
    );

    // An all-zero pair means absent, not channel 0.
    let absent = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let a = SixGhzChannels::parse(&absent).unwrap();
    assert_eq!(a.first, None, "00 00 is absent");
    assert_eq!(a.second.map(|p| p.channel), Some(17), "17 is a valid 6 GHz channel");
}
