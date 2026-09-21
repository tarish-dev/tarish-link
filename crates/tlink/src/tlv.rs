//! The TLV layer.
//!
//! Every AWDL parameter is a tag: `type(1) length(2, little-endian) value(length)`.
//! There is a short form with a one-byte length used in legacy data frames; action
//! frames always use the long form, which is all this handles.
//!
//! **The iterator stops rather than guesses.** A length that runs past the end of the
//! buffer ends iteration and is reported, because a truncated capture and a malformed
//! frame look identical here and silently trimming one to fit invents data.

pub const HEADER_LEN: usize = 3;

/// Known tag numbers. The names follow the established ones so a capture read here and
/// a capture read in Wireshark can be compared field by field.
///
/// 3 and 19 genuinely have no public name — they are on the wire and nobody has
/// published what they carry. They are left explicit rather than folded into `Unknown`
/// so that "we have seen this and do not know it" stays distinct from "we have never
/// seen this".
pub fn tag_name(t: u8) -> &'static str {
    match t {
        0 => "SSTH Request",
        1 => "Service Request",
        2 => "Service Response",
        3 => "Unknown (3)",
        4 => "Synchronization Parameters",
        5 => "Election Parameters",
        6 => "Service Parameters",
        7 => "HT Capabilities",
        8 => "Enhanced Data Rate Operation",
        9 => "Infra",
        10 => "Invite",
        11 => "Debug String",
        12 => "Data Path State",
        13 => "Encapsulated IP",
        14 => "Datapath Debug Packet Live",
        15 => "Datapath Debug AF Live",
        16 => "Arpa",
        17 => "IEEE 802.11 Container",
        18 => "Channel Sequence",
        19 => "Unknown (19)",
        20 => "Synchronization Tree",
        21 => "Version",
        22 => "Bloom Filter",
        23 => "NAN Sync",
        24 => "Election Parameters v2",
        _ => "unrecognised",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn name(&self) -> &'static str {
        tag_name(self.tag)
    }
}

/// Why iteration stopped, which is a finding in its own right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Consumed the whole region exactly. The healthy outcome.
    Clean,
    /// Fewer than 3 bytes left — not enough for another header.
    Trailing(usize),
    /// A tag claimed more bytes than the region holds.
    Overrun { tag: u8, claimed: usize, available: usize },
}

pub struct Tlvs<'a> {
    buf: &'a [u8],
    off: usize,
    stop: Option<Stop>,
}

impl<'a> Tlvs<'a> {
    pub fn new(buf: &'a [u8]) -> Tlvs<'a> {
        Tlvs { buf, off: 0, stop: None }
    }

    /// Available once iteration has finished.
    pub fn stop(&self) -> Option<Stop> {
        self.stop
    }
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        let remaining = self.buf.len() - self.off;
        if remaining == 0 {
            self.stop = Some(Stop::Clean);
            return None;
        }
        if remaining < HEADER_LEN {
            self.stop = Some(Stop::Trailing(remaining));
            return None;
        }
        let tag = self.buf[self.off];
        let len = u16::from_le_bytes([self.buf[self.off + 1], self.buf[self.off + 2]]) as usize;
        let start = self.off + HEADER_LEN;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            self.stop = Some(Stop::Overrun {
                tag,
                claimed: len,
                available: self.buf.len() - start,
            });
            return None;
        }
        self.off = end;
        Some(Tlv { tag, value: &self.buf[start..end] })
    }
}
