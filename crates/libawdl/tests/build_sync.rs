//! The Synchronization Parameters builder, against bytes real devices put on the air.
//!
//! Same rule as `build.rs`: byte equality with a capture, not a round-trip through our
//! own parser. A parser and a builder that are wrong in the same direction agree with
//! each other perfectly and with no device at all.

mod fixture_sync;

use fixture_sync::*;
use libawdl::sync::{ChanEncoding, ChannelSequence, SyncParams};

fn rebuild(original: &[u8], label: &str) {
    let parsed = SyncParams::parse(original)
        .unwrap_or_else(|| panic!("{label}: the fixture must parse"));
    let rebuilt = parsed.encode().unwrap_or_else(|| panic!("{label}: must re-encode"));

    assert_eq!(
        rebuilt.len(),
        original.len(),
        "{label}: length differs — rebuilt {} vs captured {}. The usual cause is the \
         channel count, which is stored MINUS ONE.",
        rebuilt.len(),
        original.len()
    );
    if rebuilt != original {
        let first = rebuilt.iter().zip(original).position(|(a, b)| a != b).unwrap();
        panic!(
            "{label}: byte {first} differs — rebuilt 0x{:02x}, captured 0x{:02x}",
            rebuilt[first], original[first]
        );
    }
}

#[test]
fn apple_associated_survives_parse_and_rebuild() {
    rebuild(APPLE_ASSOCIATED, "apple/associated");
}

/// The one with a non-zero value after the channel sequence.
///
/// OWL and Wireshark both call those two bytes padding. If they were, this test would
/// pass with a builder that writes zeros — it does not.
#[test]
fn a_non_zero_trailing_value_is_preserved() {
    assert_eq!(
        SyncParams::parse(APPLE_FOLLOWER).unwrap().trailing,
        [0x00, 0x4c],
        "the fixture is the one chosen for its non-zero trailing bytes"
    );
    rebuild(APPLE_FOLLOWER, "apple/follower");
}

/// A full sixteen-slot schedule in the other encoding, so the sparse fixtures above
/// cannot be passed by a builder that assumes Apple's shape.
#[test]
fn libmosey_survives_parse_and_rebuild() {
    rebuild(LIBMOSEY, "libmosey");
}

#[test]
fn the_channel_sequence_tag_survives_parse_and_rebuild() {
    let parsed = ChannelSequence::parse(APPLE_TAG18).expect("fixture parses");
    assert_eq!(parsed.encode_tag18().expect("re-encodes"), APPLE_TAG18);
}

/// Legacy stores the qualifier first and the channel second; every other encoding is the
/// other way round. A builder that gets this backwards produces a frame that parses
/// cleanly into a different schedule, which is why it is worth its own test rather than
/// being left to the fixtures.
#[test]
fn legacy_and_opclass_put_their_two_bytes_in_opposite_orders() {
    let legacy = SyncParams::parse(APPLE_ASSOCIATED).unwrap().channel_sequence.unwrap();
    assert_eq!(legacy.encoding, ChanEncoding::Legacy);
    assert_eq!(legacy.channels[8], 6, "slot 8 is channel 6");
    assert_eq!(legacy.qualifiers[8], 0x2b, "and 0x2b is its qualifier, not its channel");

    let opclass = ChannelSequence::parse(APPLE_TAG18).unwrap();
    assert_eq!(opclass.encoding, ChanEncoding::OpClass);
    assert_eq!(opclass.channels[8], 6);
    assert_eq!(opclass.qualifiers[8], 81, "operating class 81 is 2.4 GHz");
}

/// The schedule this project is for: four occupied slots out of sixteen.
#[test]
fn the_built_schedule_matches_the_shape_apple_uses() {
    let apple = SyncParams::parse(APPLE_ASSOCIATED).unwrap().channel_sequence.unwrap();
    let ours = ChannelSequence::apple_shaped(149, Some(104));

    assert_eq!(ours.channels.len(), 16);
    assert_eq!(ours.occupied_slots(), apple.occupied_slots(), "four of sixteen");
    assert_eq!(ours.channels[0], 104, "slot 0 is the association");
    assert_eq!(ours.channels[8], 6, "slot 8 is channel 6, whatever band the rest uses");
    assert_eq!(ours.slots_on(149), 2, "slots 2 and 10");

    // Occupancy must match slot for slot, not just in count -- the association and the
    // social channel differ, so comparing which slots are non-zero is the real check.
    let occupied = |c: &ChannelSequence| -> Vec<usize> {
        c.channels.iter().enumerate().filter(|(_, v)| **v != 0).map(|(i, _)| i).collect()
    };
    assert_eq!(occupied(&ours), occupied(&apple), "the same slots, not merely as many");

    // A device with no association leaves slot 0 empty, as the follower fixture does.
    assert_eq!(ChannelSequence::apple_shaped(149, None).occupied_slots(), 3);
}

/// A sequence that cannot be represented is refused, not silently truncated.
#[test]
fn an_unrepresentable_sequence_is_refused() {
    let mut seq = ChannelSequence::apple_shaped(149, Some(104));
    seq.channels.clear();
    seq.qualifiers.clear();
    assert!(seq.encode().is_none(), "zero slots has no encoding: the count is stored minus one");

    let mut unknown = ChannelSequence::apple_shaped(149, Some(104));
    unknown.encoding = ChanEncoding::Unknown(7);
    assert!(unknown.encode().is_none(), "an unknown encoding has no known stride");
}

mod fixture_frame;

/// A whole captured frame, taken apart and put back together byte for byte.
///
/// This is the test the transmitter rests on. The TLV builders each prove one tag; this
/// proves the thing that carries them — the 802.11 header, the vendor-specific action
/// wrapper, the 12-byte fixed block, and every TLV in its original order with its
/// original length encoding. A frame that differs from this by one byte is a frame an
/// Apple device may simply ignore, with nothing logged anywhere to say why.
#[test]
fn a_whole_apple_frame_survives_parse_and_rebuild() {
    use libawdl::{action::ActionFrame, dot11::{management_header, Dot11, Mac}, radiotap::Radiotap};

    let rt = Radiotap::parse(fixture_frame::FRAME).expect("radiotap parses");
    let body80211 = rt.payload(fixture_frame::FRAME).expect("has a payload");
    let d = Dot11::parse(body80211).expect("802.11 header parses");
    assert!(d.is_action());

    // The 802.11 header, rebuilt from its parsed parts.
    let seq = u16::from_le_bytes([body80211[22], body80211[23]]) >> 4;
    let rebuilt_hdr = management_header(d.dst, d.src, seq);
    assert_eq!(
        &rebuilt_hdr[..],
        &body80211[..24],
        "the 24-byte management header differs; duration and the BSSID are the usual causes"
    );
    assert_eq!(d.bssid, Mac(libawdl::action::BSSID), "every AWDL frame carries this BSSID");

    // The action frame body, rebuilt from its parsed parts.
    let af = ActionFrame::parse(&body80211[24..]).expect("AWDL action frame parses");
    let tlvs: Vec<(u8, Vec<u8>)> = af.tlvs().map(|t| (t.tag, t.value.to_vec())).collect();
    assert!(tlvs.len() > 3, "the fixture carries a real set of tags, not one");

    let rebuilt = libawdl::action::encode_body(&af.fixed, &tlvs);
    let original = &body80211[24..];
    assert_eq!(
        rebuilt.len(),
        original.len(),
        "body length differs — rebuilt {} vs captured {}",
        rebuilt.len(),
        original.len()
    );
    if rebuilt != original {
        let i = rebuilt.iter().zip(original).position(|(a, b)| a != b).unwrap();
        panic!("body byte {i} differs: rebuilt 0x{:02x}, captured 0x{:02x}", rebuilt[i], original[i]);
    }
}

/// The header version is a packed pair of nibbles, and it is NOT the version in tag 21.
#[test]
fn the_header_version_is_one_point_oh_and_is_not_tag_21() {
    use libawdl::action::{Fixed, HEADER_VERSION};

    let f = Fixed::for_tx(libawdl::action::SUBTYPE_MIF, 0x1234_5678);
    assert_eq!(f.version_major, 1);
    assert_eq!(f.version_minor, 0);
    assert_eq!(f.encode()[5], HEADER_VERSION, "0x10 is 1.0, not 16");
    assert_eq!(f.encode()[5], 0x10);
}

/// Broadcast frames carry duration 0; unicast frames carry 48. Measured, both.
#[test]
fn duration_follows_the_destination() {
    use libawdl::dot11::{management_header, Mac, BROADCAST};

    let src = Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(management_header(BROADCAST, src, 0)[2..4], [0, 0]);
    assert_eq!(management_header(Mac([0x8a; 6]), src, 0)[2..4], [48, 0]);
}
