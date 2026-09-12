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
