//! What we can NAME, as distinct from what we can reproduce.
//!
//! These are regression tests on honesty. The builders all pass byte-equality tests, and
//! it would be easy to read that as "the protocol is understood". It is not, and this
//! pins the actual figure so it cannot drift upward in anyone's memory.

mod fixture_sync;
mod fixture_election;

use libawdl::coverage::{is_decoded, of_tlv};

/// Synchronization Parameters: three-quarters named, and the missing quarter is specific.
#[test]
fn sync_params_are_not_fully_understood() {
    let c = of_tlv(4, fixture_sync::APPLE_ASSOCIATED);
    assert_eq!(c.total(), 73);
    // flags(2) + byte 28(1) + trailing(2) + sixteen Legacy qualifier bytes.
    assert_eq!(c.opaque, 21, "and every one of them round-trips regardless");
    assert!(c.percent_named() > 70.0 && c.percent_named() < 75.0, "{}", c.percent_named());

    // The same schedule in the other encoding hides less: an operating class is a value
    // we can choose, a Legacy flags byte is not.
    let op = of_tlv(18, fixture_sync::APPLE_TAG18);
    assert_eq!(op.opaque, 0, "OpClass qualifiers are operating classes, which we can name");
}

/// Election v2 is the worst of the tags we do parse.
#[test]
fn election_v2_is_less_than_half_named() {
    let c = of_tlv(24, fixture_election::APPLE_ELECTION_V2);
    assert_eq!(c.total(), 40);
    assert_eq!(c.named, 18, "master, distance, and the two metrics");
    assert_eq!(c.opaque, 22, "the second address, both counters, and eight reserved bytes");
    assert!(c.percent_named() < 50.0);
}

/// The tags with no decoder at all. Naming them here means adding one is a visible change.
#[test]
fn the_undecoded_tags_are_the_ones_we_think_they_are() {
    for tag in [6u8, 7, 35] {
        assert!(!is_decoded(tag), "tag {tag} has no parser");
        let c = of_tlv(tag, &[1, 2, 3, 4]);
        assert_eq!(c.named, 0, "tag {tag} contributes nothing we can name");
        assert_eq!(c.opaque, 4);
    }
    for tag in [2u8, 4, 5, 12, 16, 17, 18, 21, 24, 32, 33] {
        assert!(is_decoded(tag), "tag {tag} has a parser");
    }
}

/// A zero-length tag is a presence flag. It has no bytes, so it is neither understood
/// nor not — and reporting it as 0% understood would be wrong.
#[test]
fn a_zero_length_tag_has_nothing_to_understand() {
    let c = of_tlv(0, &[]);
    assert_eq!(c.total(), 0);
    assert_eq!(c.percent_named(), 0.0, "and the CLI prints n/a rather than 0%");
}

/// Service Response really is fully understood: it is DNS, and the builder reproduces a
/// captured record set byte for byte including its compression pointers.
#[test]
fn service_response_is_the_one_tag_we_fully_understand() {
    let c = of_tlv(2, &[0u8; 40]);
    assert_eq!(c.opaque, 0);
}
