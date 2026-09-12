//! The builder, tested against bytes a real Apple device put on the air.
//!
//! A serialiser that only round-trips through its own parser proves nothing: a matched
//! pair of mistakes passes such a test perfectly. So the fixture here is a captured
//! Service Response TLV, and the requirement is **byte equality** with it.

mod fixture_service;

use libawdl::service::{encode_name, encode_records, records, Record};

/// Parse a real TLV, re-serialise it, and require identical bytes.
///
/// This is the only test in the suite that can catch a builder and parser that are wrong
/// in the same direction — which is the failure mode a round-trip test normally hides.
#[test]
fn a_real_tlv_survives_parse_and_rebuild_unchanged() {
    let original = fixture_service::TLV;
    let parsed = records(original);
    assert!(!parsed.is_empty(), "the fixture holds at least one record");

    let rebuilt = encode_records(&parsed);

    assert_eq!(
        rebuilt.len(),
        original.len(),
        "length differs: rebuilt {} vs captured {} — most likely the name-length field, \
         which includes the type byte that follows it",
        rebuilt.len(),
        original.len()
    );
    assert_eq!(rebuilt, original, "rebuilt bytes differ from what the device sent");
}

/// Compression must pick the LONGEST matching suffix.
///
/// Both `_airdrop._tcp.local` (0xC007) and `local` (0xC00C) match the end of an AirDrop
/// instance name. Choosing the shorter one produces a longer, still-parseable frame that
/// no Apple device would have emitted — wrong in a way nothing errors on.
#[test]
fn names_compress_to_the_longest_dictionary_match() {
    // The whole name is a dictionary entry.
    assert_eq!(encode_name("_airdrop._tcp.local"), vec![0xC0, 0x07]);

    // One label, then the compressed suffix.
    let n = encode_name("c58953abded2._airdrop._tcp.local");
    assert_eq!(n[0], 12, "label length byte for the 12-hex instance id");
    assert_eq!(&n[1..13], b"c58953abded2");
    assert_eq!(&n[13..], &[0xC0, 0x07], "longest suffix wins, not 0xC00C for 'local'");

    // A host name whose only dictionary match is `local`. Ends at the code, so no
    // terminator follows it.
    let h = encode_name("21327096-a4e8-484d-bf46-833b2af9e6e8.local");
    assert_eq!(&h[h.len() - 2..], &[0xC0, 0x0C]);

    // Nothing matches: every label spelled out, then the 0xC000 terminator.
    //
    // This expectation originally omitted the terminator, which is what the captured
    // frame taught us was wrong -- see the byte-equality test above.
    let p = encode_name("example.invalid");
    let mut want = vec![7];
    want.extend_from_slice(b"example");
    want.push(7);
    want.extend_from_slice(b"invalid");
    want.extend_from_slice(&[0xC0, 0x00]);
    assert_eq!(p, want);
}

/// The records `libawdl` has to emit to be discoverable at all, built from scratch.
///
/// OWL sends **zero** Service Response records against Apple's 1620 in a comparable
/// capture, so a peer that synchronises with it perfectly still finds nothing to talk to.
/// This is the minimum set, and it must survive a parse.
#[test]
fn a_discoverable_advertisement_can_be_built_from_nothing() {
    let instance = "a1b2c3d4e5f6";
    let host = "tarish-1.local";

    let built = encode_records(&[
        Record::Ptr {
            name: "_airdrop._tcp.local".into(),
            target: format!("{instance}._airdrop._tcp.local"),
        },
        Record::Srv {
            name: format!("{instance}._airdrop._tcp.local"),
            priority: 0,
            weight: 0,
            // 8770, read off the air rather than assumed -- see FINDINGS 14.
            port: 8770,
            target: host.into(),
        },
        Record::Txt {
            name: format!("{instance}._airdrop._tcp.local"),
            strings: vec!["flags=111611".into()],
        },
    ]);

    let back = records(&built);
    assert_eq!(back.len(), 3, "three records in, three out");

    match &back[1] {
        Record::Srv { port, target, .. } => {
            assert_eq!(*port, 8770, "big-endian on the wire; 8770 read the other way is 16418");
            assert_eq!(target, host);
        }
        other => panic!("expected the SRV second, got {other:?}"),
    }
    match &back[0] {
        Record::Ptr { name, target } => {
            assert_eq!(name, "_airdrop._tcp.local");
            assert!(target.starts_with(instance));
        }
        other => panic!("expected the PTR first, got {other:?}"),
    }
}
