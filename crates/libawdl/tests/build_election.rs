//! Election, Arpa and Version builders, against captured bytes.

mod fixture_election;

use fixture_election::*;
use libawdl::{
    election::{ElectionParams, ElectionParamsV2},
    state::{Arpa, Version},
};

fn same(rebuilt: &[u8], original: &[u8], label: &str) {
    assert_eq!(rebuilt.len(), original.len(), "{label}: length {} vs {}", rebuilt.len(), original.len());
    if rebuilt != original {
        let i = rebuilt.iter().zip(original).position(|(a, b)| a != b).unwrap();
        panic!("{label}: byte {i} differs — rebuilt 0x{:02x}, captured 0x{:02x}", rebuilt[i], original[i]);
    }
}

/// The tag is 21 bytes and the named fields account for 19.
///
/// A builder that stops at 19 produces a tag two bytes short of anything a real device
/// sends, and nothing errors — the TLV length simply says 19 and the next tag follows.
#[test]
fn election_v1_survives_parse_and_rebuild() {
    let p = ElectionParams::parse(APPLE_ELECTION).expect("parses");
    assert_eq!(APPLE_ELECTION.len(), 21);
    assert_eq!(p.tail.len(), 2, "two bytes past the named fields");
    assert!(p.claims_mastership());
    assert_eq!(p.self_metric, 530);
    same(&p.encode(), APPLE_ELECTION, "election v1");
}

#[test]
fn election_v2_survives_parse_and_rebuild() {
    let p = ElectionParamsV2::parse(APPLE_ELECTION_V2).expect("parses");
    assert_eq!(p.self_metric, 530);
    assert_eq!(p.master, p.other, "the second address is this device's own");
    same(&p.encode(), APPLE_ELECTION_V2, "election v2");
}

/// A claim we make ourselves has the shape of a real one.
#[test]
fn our_own_claim_has_the_shape_of_a_real_one() {
    let addr = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let v1 = ElectionParams::claiming(addr, 530);
    let v2 = ElectionParamsV2::claiming(addr, 530, 5);

    assert_eq!(v1.encode().len(), APPLE_ELECTION.len(), "same length as Apple's");
    assert_eq!(v2.encode().len(), APPLE_ELECTION_V2.len());
    assert!(v1.claims_mastership() && v2.claims_mastership());
    assert_eq!(v1.master, addr, "claiming the job means naming yourself as master");

    // Round-trips through the parser as what it claims to be.
    let back = ElectionParams::parse(&v1.encode()).expect("our own tag parses");
    assert_eq!(back, v1);
    let back2 = ElectionParamsV2::parse(&v2.encode()).expect("our own tag parses");
    assert_eq!(back2, v2);
}

/// A metric beats a counter, which is the correction in `beats`.
#[test]
fn the_higher_metric_wins_regardless_of_counter() {
    let a = [0x6a, 0x89, 0xd8, 0xa5, 0x88, 0x9b];
    let b = [0xbe, 0x35, 0xbe, 0xc9, 0x05, 0x1f];
    // The capture: 6a:89 had metric 510 and counter 68364, and followed be:35 at 520.
    let weak = ElectionParamsV2::claiming(a, 510, 68364);
    let strong = ElectionParamsV2::claiming(b, 520, 608);
    assert!(strong.beats(&weak, b, a), "520 beats 510");
    assert!(!weak.beats(&strong, a, b), "a counter 112x larger does not");
}

#[test]
fn arpa_survives_parse_and_rebuild_with_its_compression_pointer() {
    let p = Arpa::parse(APPLE_ARPA).expect("parses");
    // 0x24 at the front is the label LENGTH (36, the width of a UUID), not a '$' --
    // which is what that byte happens to be in ASCII, and an easy misread.
    assert_eq!(p.name, "790ea13a-d6d4-4995-acab-79a2e5279f2a.local");
    assert!(p.name.ends_with("local"), "the pointer expands to local: {:?}", p.name);
    same(&p.encode(), APPLE_ARPA, "arpa");
}

/// The two versions that define §1 of the gap table.
#[test]
fn version_packs_nibbles_and_both_vendors_round_trip() {
    let apple = Version::parse(APPLE_VERSION).expect("parses");
    assert_eq!((apple.major, apple.minor), (10, 0), "0xa0 is 10.0, not 160");
    same(&apple.encode(), APPLE_VERSION, "apple version");

    let mosey = Version::parse(LIBMOSEY_VERSION).expect("parses");
    assert_eq!((mosey.major, mosey.minor), (3, 4));
    assert_eq!(mosey.device_class, apple.device_class, "same class, different version");
    same(&mosey.encode(), LIBMOSEY_VERSION, "libmosey version");
}

/// Data Path State is a bitmap followed by only the fields the bitmap claims, so a
/// builder that writes the fields in bit order gets every offset after the first wrong —
/// and produces a tag that parses cleanly into different values.
#[test]
fn data_path_state_survives_parse_and_rebuild() {
    use libawdl::state::{flag, DataPathState};

    let p = DataPathState::parse(APPLE_DATAPATH).expect("parses");
    assert!(p.is_associated(), "the fixture is an associated device");
    assert_eq!(p.infra_channel, Some(104), "the AP's channel, matching slot 0");
    assert_eq!(p.country.as_deref(), Some("QA"));
    assert!(p.flags & flag::EXTENDED != 0, "and it carries the extended block");
    same(&p.encode(), APPLE_DATAPATH, "data path state");
}

/// One we describe ourselves, and the association it claims.
#[test]
fn our_data_path_state_states_the_association_once_per_place_it_belongs() {
    use libawdl::state::DataPathState;

    let awdl = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let d = DataPathState::describing(awdl, "QA", 149, Some((bssid, 104)));

    let back = DataPathState::parse(&d.encode()).expect("our own tag parses");
    assert_eq!(back, d, "the bitmap and the field order agree with the parser");
    assert!(back.is_associated());
    assert_eq!(back.infra_channel, Some(104));
    assert_eq!(back.country.as_deref(), Some("QA"));

    // No association: the flag goes away and so do the two fields behind it.
    let alone = DataPathState::describing(awdl, "QA", 149, None);
    assert!(!alone.is_associated());
    assert_eq!(DataPathState::parse(&alone.encode()).unwrap(), alone);
    assert!(alone.encode().len() < d.encode().len(), "fewer fields, shorter tag");
}

/// Tag 17 carries standard 802.11 elements, not a format of AWDL's own.
#[test]
fn the_container_holds_a_vht_capabilities_element() {
    use libawdl::state::{Ieee80211Container, ELEM_VHT_CAPABILITIES};

    let c = Ieee80211Container::parse(APPLE_CONTAINER).expect("parses");
    assert_eq!(c.elements.len(), 1, "one element");
    assert_eq!(c.elements[0].0, ELEM_VHT_CAPABILITIES);
    assert_eq!(c.vht_capabilities().map(|b| b.len()), Some(12), "4 of capability info, 8 of MCS/NSS");
    same(&c.encode(), APPLE_CONTAINER, "802.11 container");

    // An element whose length runs past the end is refused, not trimmed.
    assert!(Ieee80211Container::parse(&[0xbf, 0x40, 0x00]).is_none());
}
