//! What we can NAME, as distinct from what we can reproduce.
//!
//! These are regression tests on honesty. The builders all pass byte-equality tests, and
//! it would be easy to read that as "the protocol is understood". It is not, and this
//! pins the actual figure so it cannot drift upward in anyone's memory.

mod fixture_sync;
mod fixture_election;

use libawdl::coverage::{is_decoded, of_tlv};

/// Synchronization Parameters, once the Legacy qualifier is decoded.
///
/// It was 21 opaque bytes of 73. Sixteen of those were the qualifier byte on each slot,
/// recovered by pairing tag 4 against tag 18 in the same frame, which leaves five: the
/// flags word, byte 28, and the two trailing bytes.
#[test]
fn sync_params_have_five_opaque_bytes_left() {
    let c = of_tlv(4, fixture_sync::APPLE_ASSOCIATED);
    assert_eq!(c.total(), 73);
    assert_eq!(c.opaque, 5, "the flags word, byte 28, and the trailing pair");
    assert_eq!(c.named, 68);

    let op = of_tlv(18, fixture_sync::APPLE_TAG18);
    assert_eq!(op.opaque, 0, "OpClass qualifiers are operating classes");
}

/// Election v2, once the counters are a tenure and the second address is the parent.
///
/// It was 22 opaque bytes of 40: the counters accounted for eight and the parent for six,
/// which leaves the eight reserved bytes at offset 28 and nothing else.
#[test]
fn election_v2_has_eight_opaque_bytes_left() {
    let c = of_tlv(24, fixture_election::APPLE_ELECTION_V2);
    assert_eq!(c.total(), 40);
    assert_eq!(c.named, 32, "master, parent, distance, both metrics, both counters");
    assert_eq!(c.opaque, 8, "the reserved block at offset 28, and only that");
}

/// The tags with no decoder at all. Naming them here means adding one is a visible change.
#[test]
fn the_undecoded_tags_are_the_ones_we_think_they_are() {
    // Tag 35 has no parser at all.
    assert!(!is_decoded(35));
    let c = of_tlv(35, &[1, 2, 3, 4]);
    assert_eq!(c.named, 0);
    assert_eq!(c.opaque, 4);

    // Tag 6 HAS a parser and still names nothing, which is the distinction worth keeping:
    // its field boundaries are known and its contents are a hash we cannot compute.
    // Knowing where a field starts is not knowing what belongs in it.
    assert!(is_decoded(6), "there is a parser");
    let six = of_tlv(6, &[0u8; 11]);
    assert_eq!(six.named, 0, "and it names nothing");
    assert_eq!(six.opaque, 11);

    for tag in [2u8, 4, 5, 7, 12, 16, 17, 18, 21, 24, 32, 33] {
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

/// HT Capabilities, once the "undecoded tail" turned out to be the rest of a standard
/// field. Truncation is the whole story: the same structure stops in three places.
#[test]
fn ht_capabilities_are_named_for_as_much_mcs_set_as_they_carry() {
    use fixture_election::{APPLE_HT_LONG, APPLE_HT_SHORT};

    // Two leading bytes opaque in every shape -- `00 00` everywhere measured, which is not
    // the same as knowing what they are. Everything else is an 802.11 field.
    let long = of_tlv(7, APPLE_HT_LONG);
    assert_eq!(long.total(), 20);
    assert_eq!(long.opaque, 2, "only the two unnamed leading bytes");
    assert_eq!(long.named, 18);

    let short = of_tlv(7, APPLE_HT_SHORT);
    assert_eq!(short.total(), 9);
    assert_eq!(short.opaque, 2);
    assert_eq!(short.named, 7);

    // A TLV longer than the structure does not get credit for the excess: 5 header bytes
    // plus at most 16 MCS octets is all that 802.11 defines.
    let over = of_tlv(7, &[0u8; 40]);
    assert_eq!(over.named, 3 + 16);
    assert_eq!(over.opaque, 40 - 19, "past the MCS set we are back to guessing");
}
