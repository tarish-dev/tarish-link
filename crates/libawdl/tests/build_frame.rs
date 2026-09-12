//! Build a Master Indication Frame from nothing, and check it against a real one.
//!
//! Every other builder test proves one tag reproduces bytes a device sent. This one asks
//! the question those cannot: **if we assembled a frame ourselves, would it have the shape
//! of a frame an Apple device would act on?**
//!
//! It cannot prove a peer accepts it — only a radio can do that. What it can do is catch
//! the ways a frame is wrong before it ever reaches one, and those are mostly ways that
//! raise no error anywhere: a missing tag, a tag whose length field disagrees with its
//! contents, tags in an order no device uses.

mod fixture_frame;

use libawdl::{
    action::{self, ActionFrame, Fixed, SUBTYPE_MIF},
    dot11::{management_header, Dot11, Mac, BROADCAST},
    election::{ElectionParams, ElectionParamsV2},
    radiotap::Radiotap,
    service::{self, Record},
    state::{Arpa, DataPathState, Ieee80211Container, Version, ELEM_VHT_CAPABILITIES},
    sync::{ChannelSequence, SyncParams},
};

const OUR_ADDR: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP_BSSID: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const METRIC: u32 = 530;

/// A VHT Capabilities body of the right length. **Not a claim about any real radio** —
/// the HAL owns these bits, and this exists so the frame has the right shape in a test
/// that has no radio.
const PLACEHOLDER_VHT: &[u8; 12] = &[0x32, 0x00, 0x80, 0x03, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0];

/// Assemble a MIF the way a transmitter would.
fn build_mif() -> Vec<u8> {
    let seq = ChannelSequence::apple_shaped(149, Some(104));

    let sync = SyncParams {
        tx_channel: 149,
        tx_counter: 0,
        master_channel: 149,
        guard_time: 0,
        aw_period: 16,
        action_frame_period: 110,
        flags: 0x1800,
        aw_ext_length: 16,
        aw_common_length: 16,
        aw_remaining: 0,
        ext_min: 3,
        ext_max_multicast: 3,
        ext_max_unicast: 3,
        ext_max_af: 3,
        master: OUR_ADDR,
        presence_mode: 4,
        reserved_28: 0,
        aw_counter: 0,
        ap_beacon_alignment_delta: 0,
        channel_sequence: Some(seq.clone()),
        // Zero, which is what OWL writes and what every associated Apple device writes.
        trailing: [0, 0],
    };

    let tlvs: Vec<(u8, Vec<u8>)> = vec![
        (4, sync.encode().expect("sync encodes")),
        (18, seq.encode_tag18().expect("sequence encodes")),
        (5, ElectionParams::claiming(OUR_ADDR, METRIC).encode()),
        (24, ElectionParamsV2::claiming(OUR_ADDR, METRIC, 5).encode()),
        (
            12,
            DataPathState::describing(OUR_ADDR, "QA", 149, Some((AP_BSSID, 104))).encode(),
        ),
        (
            17,
            Ieee80211Container {
                // The radio's own capabilities. These twelve bytes belong to the HAL --
                // they describe hardware -- and the value here is a placeholder standing in
                // until one supplies them, which is why it is named rather than inlined.
                elements: vec![(ELEM_VHT_CAPABILITIES, PLACEHOLDER_VHT.to_vec())],
            }
            .encode(),
        ),
        (16, Arpa { flags: 3, name: "tarish.local".into() }.encode()),
        (21, Version { major: 3, minor: 4, device_class: 2 }.encode().to_vec()),
        (
            2,
            service::encode_records(&[Record::Ptr {
                name: "_airdrop._tcp.local".into(),
                target: "0011223344556677._airdrop._tcp.local".into(),
            }]),
        ),
    ];

    let mut frame = management_header(BROADCAST, Mac(OUR_ADDR), 0).to_vec();
    frame.extend_from_slice(&action::encode_body(&Fixed::for_tx(SUBTYPE_MIF, 0), &tlvs));
    frame
}

/// The frame we built parses as AWDL, through the same code that reads the air.
#[test]
fn a_frame_we_built_parses_as_awdl() {
    let frame = build_mif();

    let d = Dot11::parse(&frame).expect("802.11 header parses");
    assert!(d.is_action(), "management/action");
    assert_eq!(d.bssid, Mac(action::BSSID));
    assert_eq!(d.dst, BROADCAST);

    let af = ActionFrame::parse(&frame[24..]).expect("recognised as AWDL");
    assert_eq!(af.fixed.subtype, SUBTYPE_MIF);
    assert_eq!((af.fixed.version_major, af.fixed.version_minor), (1, 0));

    // Every tag must come back out with its length intact. `Tlvs` stops rather than
    // guesses when a length runs past the end, so a short count here is a real defect.
    let tags: Vec<u8> = af.tlvs().map(|t| t.tag).collect();
    assert_eq!(tags, vec![4, 18, 5, 24, 12, 17, 16, 21, 2], "nine tags, in the order written");

    let sync = af.tlvs().find(|t| t.tag == 4).map(|t| SyncParams::parse(t.value));
    let sync = sync.flatten().expect("our own sync params parse");
    assert_eq!(sync.aw_period, 16);
    let seq = sync.channel_sequence.expect("carries a schedule");
    assert_eq!(seq.channels[8], 6, "slot 8 is channel 6");
    assert_eq!(seq.occupied_slots(), 4);
}

/// The tag set against what a real Apple device puts in a frame.
///
/// Not byte equality — the contents are ours and must differ. The check is which tags we
/// still cannot build, and it is written as an exact set so the gap cannot grow unnoticed
/// and cannot shrink without someone updating the list and saying why.
///
/// The four that remain are not the same kind of gap:
///
/// - **6, Service Parameters** and **7, HT Capabilities** are undecoded. Their captured
///   values have no published layout and no structure we have recovered — tag 7 is 9 bytes
///   from one device and 20 from another, which is not a fixed struct. Emitting bytes we
///   cannot describe would be guessing on the air.
/// - **32 and 33** are the 6 GHz tags, and their absence here is correct: the frame under
///   test claims a 5 GHz association, and a device sends these when it has a 6 GHz one.
///   They are a conditional field, not a missing one.
#[test]
fn the_tags_we_still_cannot_build_are_exactly_the_four_we_know_about() {
    use std::collections::BTreeSet;

    let rt = Radiotap::parse(fixture_frame::FRAME).unwrap();
    let real = rt.payload(fixture_frame::FRAME).unwrap();
    let real_af = ActionFrame::parse(&real[24..]).unwrap();
    let theirs: BTreeSet<u8> = real_af.tlvs().map(|t| t.tag).collect();

    let frame = build_mif();
    let ours: BTreeSet<u8> = ActionFrame::parse(&frame[24..]).unwrap().tlvs().map(|t| t.tag).collect();

    let missing: Vec<u8> = theirs.difference(&ours).copied().collect();
    assert_eq!(
        missing,
        vec![6, 7, 32, 33],
        "the set of tags we cannot build changed — now missing {}",
        missing.iter().map(|t| libawdl::tlv::tag_name(*t)).collect::<Vec<_>>().join(", ")
    );

    // And everything Apple sends that is not on that list, we do send.
    for tag in theirs.iter().filter(|t| !missing.contains(t)) {
        assert!(ours.contains(tag), "tag {tag} ({}) is missing", libawdl::tlv::tag_name(*tag));
    }
}

/// Our frame is a plausible size next to a real one.
///
/// A frame an order of magnitude off is usually a length field written in the wrong
/// endianness or a tag body that was never appended, both of which still parse.
#[test]
fn our_frame_is_a_plausible_size() {
    let rt = Radiotap::parse(fixture_frame::FRAME).unwrap();
    let real = rt.payload(fixture_frame::FRAME).unwrap();
    let ours = build_mif();
    let ratio = ours.len() as f64 / real.len() as f64;
    assert!(
        (0.4..=1.6).contains(&ratio),
        "built {} bytes against a real {} ({ratio:.2}x)",
        ours.len(),
        real.len()
    );
}
