//! Service Response (tag 2) — mDNS records carried inside AWDL action frames.
//!
//! This is the densest tag in the protocol: 576 records in one 45s capture, 1038 in
//! another. It is also the one that makes a capture legible, because it carries the
//! device name, the service instance and the port — the things a person would recognise.
//!
//! **AWDL does not carry mDNS verbatim.** It carries the same records under its own
//! encoding, with a fixed dictionary so that the strings every AirDrop frame would
//! otherwise repeat cost two bytes instead of twenty:
//!
//! ```text
//!   0xC007  ->  _airdrop._tcp.local
//!   0xC00C  ->  local
//! ```
//!
//! The dictionary is static and shared by every implementation — there is no negotiation
//! and no per-frame table, so a decoder either knows these values or produces nonsense
//! that still parses.

use crate::le;

/// Dictionary for compressed labels. Codes are big-endian and have the top two bits set,
/// which is how they are told apart from a length byte.
pub fn compressed_label(code: u16) -> Option<&'static str> {
    Some(match code {
        // 0xC000 is a NULL label: structurally present, contributes nothing to the name.
        0xC000 => return None,
        0xC001 => "_airplay._tcp.local",
        0xC002 => "_airplay._udp.local",
        0xC003 => "_airplay",
        0xC004 => "_raop._tcp.local",
        0xC005 => "_raop._udp.local",
        0xC006 => "_raop",
        0xC007 => "_airdrop._tcp.local",
        0xC008 => "_airdrop._udp.local",
        0xC009 => "_airdrop",
        0xC00A => "_tcp.local",
        0xC00B => "_udp.local",
        0xC00C => "local",
        0xC00D => "ip6.arpa",
        0xC00E => "ip4.arpa",
        _ => "<unknown-code>",
    })
}

/// Decode a name from `buf[0..len]`, returning the name and how many bytes were consumed.
///
/// A label is either a length byte followed by that many ASCII bytes, or — when the top
/// two bits are set — a two-byte big-endian dictionary code.
pub fn decode_name(buf: &[u8], len: usize) -> Option<(String, usize)> {
    let mut out: Vec<String> = Vec::new();
    let mut off = 0usize;
    while off < len {
        let first = le::u8(buf, off)?;
        if first & 0xC0 != 0 {
            let code = u16::from_be_bytes([first, le::u8(buf, off + 1)?]);
            if let Some(s) = compressed_label(code) {
                out.push(s.to_string());
            }
            off += 2;
        } else {
            let n = first as usize;
            let bytes = buf.get(off + 1..off + 1 + n)?;
            // Names are ASCII on the wire; anything else is a decode error rather than
            // something to render optimistically.
            out.push(String::from_utf8_lossy(bytes).into_owned());
            off += 1 + n;
        }
    }
    Some((out.join("."), off))
}

pub const T_PTR: u8 = 12;
pub const T_TXT: u8 = 16;
pub const T_SRV: u8 = 33;

pub fn type_name(t: u8) -> &'static str {
    match t {
        1 => "A",
        T_PTR => "PTR",
        T_TXT => "TXT",
        28 => "AAAA",
        T_SRV => "SRV",
        _ => "?",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Points a service type at an instance: `_airdrop._tcp.local -> abc123._airdrop…`
    Ptr { name: String, target: String },
    /// Where to actually connect. The port here is the AirDrop HTTPS port.
    Srv { name: String, priority: u16, weight: u16, port: u16, target: String },
    /// Key/value strings. Carries the AirDrop flags and capability bits.
    Txt { name: String, strings: Vec<String> },
    /// A record type we do not decode yet, kept rather than dropped.
    Other { name: String, rtype: u8, data: Vec<u8> },
}

impl Record {
    pub fn name(&self) -> &str {
        match self {
            Record::Ptr { name, .. }
            | Record::Srv { name, .. }
            | Record::Txt { name, .. }
            | Record::Other { name, .. } => name,
        }
    }

    /// Parse one record, returning it and the bytes consumed.
    pub fn parse(v: &[u8]) -> Option<(Record, usize)> {
        // THE NAME LENGTH INCLUDES THE TYPE BYTE THAT FOLLOWS IT. Taking it at face
        // value runs the name decoder one byte into the type field, which yields a name
        // with a spurious trailing label and leaves every later offset wrong.
        let name_len = le::u16(v, 0)? as usize;
        if name_len == 0 {
            return None;
        }
        let name_len = name_len - 1;

        let (name, used) = decode_name(v.get(2..)?, name_len)?;
        let mut off = 2 + used;

        let rtype = le::u8(v, off)?;
        off += 1;
        let data_len = le::u16(v, off)? as usize;
        off += 2;
        // Two bytes upstream calls unknown. Consistently zero in captures so far, and
        // left undecoded rather than assumed to be padding.
        off += 2;

        let rec = match rtype {
            T_PTR => {
                let (target, _) = decode_name(v.get(off..)?, data_len)?;
                Record::Ptr { name, target }
            }
            T_SRV => {
                // Big-endian here, unlike everything else in AWDL — these three fields
                // are DNS's own layout, carried through unchanged.
                let priority = u16::from_be_bytes([le::u8(v, off)?, le::u8(v, off + 1)?]);
                let weight = u16::from_be_bytes([le::u8(v, off + 2)?, le::u8(v, off + 3)?]);
                let port = u16::from_be_bytes([le::u8(v, off + 4)?, le::u8(v, off + 5)?]);
                let (target, _) = decode_name(v.get(off + 6..)?, data_len.checked_sub(6)?)?;
                Record::Srv { name, priority, weight, port, target }
            }
            T_TXT => {
                let mut strings = Vec::new();
                let mut p = 0usize;
                let body = v.get(off..off + data_len)?;
                while p < body.len() {
                    let n = body[p] as usize;
                    let s = body.get(p + 1..p + 1 + n)?;
                    strings.push(String::from_utf8_lossy(s).into_owned());
                    p += 1 + n;
                }
                Record::Txt { name, strings }
            }
            _ => Record::Other { name, rtype, data: v.get(off..off + data_len)?.to_vec() },
        };
        Some((rec, off + data_len))
    }
}

/// Every record in one Service Response TLV. A single TLV can hold several.
pub fn records(v: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < v.len() {
        match Record::parse(&v[off..]) {
            Some((r, used)) if used > 0 => {
                out.push(r);
                off += used;
            }
            // Stop rather than resync. A record that will not parse means the offsets
            // are already wrong, and guessing where the next one starts manufactures
            // records that were never on the air.
            _ => break,
        }
    }
    out
}

// ---------------------------------------------------------------- building ---
//
// The inverse of everything above. `libawdl` has to *emit* these records, not only read
// them: OWL sends zero Service Response records against Apple's 1620 in a comparable
// capture, so a peer synchronising with it perfectly still has nothing to discover.
//
// The test that matters for a builder is not "does it produce something parseable" but
// "does it produce the same bytes a real device produced". `tests/fixture_service.rs`
// holds a captured TLV and the round-trip test requires byte equality.

/// Encode a name, compressing any suffix that the dictionary covers.
///
/// **Compression is not optional.** A receiver is not obliged to accept a name spelled out
/// in full where a code exists, and more practically: Apple's own frames use the codes, so
/// a frame that does not is distinguishable from a real one. Matching the wire is the whole
/// job.
///
/// The dictionary entries are multi-label suffixes (`_airdrop._tcp.local`), so the longest
/// matching suffix is what to look for — greedy from the end, not label by label.
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = name;

    loop {
        if rest.is_empty() {
            break;
        }
        // Longest suffix first: "_airdrop._tcp.local" must win over "local".
        let mut best: Option<(usize, u16)> = None;
        for code in 0xC001u16..=0xC00E {
            let Some(text) = compressed_label(code) else { continue };
            if rest == text || rest.ends_with(&format!(".{text}")) {
                let prefix_len = rest.len() - text.len();
                if best.map_or(true, |(l, _)| text.len() > rest.len() - l) {
                    best = Some((prefix_len, code));
                }
            }
        }

        if let Some((prefix_len, code)) = best {
            // Emit any labels before the compressed suffix, then the code.
            let prefix = rest[..prefix_len].trim_end_matches('.');
            for label in prefix.split('.').filter(|l| !l.is_empty()) {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.extend_from_slice(&code.to_be_bytes());
            return out;
        }

        // Nothing in the dictionary matches: spell the remaining labels out, then
        // terminate.
        //
        // A NAME ENDING IN A LITERAL LABEL IS TERMINATED WITH 0xC000. One ending in a
        // dictionary code is not — the code implies the end. Observed in a captured
        // frame: the PTR target `iPhone (2)` is `0a "iPhone (2)" c0 00`, while the record
        // name `_applicationservicepairing._tcp.local` ends at its `c0 0a` code with no
        // terminator.
        //
        // 0xC000 decodes to nothing, so omitting it produces a name that reads back
        // correctly and is two bytes shorter than what the device sent. A round-trip
        // test against our own parser passes either way; only byte equality with a real
        // frame catches it.
        for label in rest.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.extend_from_slice(&0xC000u16.to_be_bytes());
        rest = "";
    }
    out
}

impl Record {
    /// Serialise this record as it appears inside a Service Response TLV.
    pub fn encode(&self) -> Vec<u8> {
        let (name, rtype) = match self {
            Record::Ptr { name, .. } => (name.as_str(), T_PTR),
            Record::Srv { name, .. } => (name.as_str(), T_SRV),
            Record::Txt { name, .. } => (name.as_str(), T_TXT),
            Record::Other { name, rtype, .. } => (name.as_str(), *rtype),
        };

        let encoded_name = encode_name(name);
        let mut out = Vec::new();

        // THE LENGTH INCLUDES THE TYPE BYTE THAT FOLLOWS IT. The parser has to subtract
        // one; the builder has to add one. Getting this wrong here produces a frame that
        // our own parser reads back correctly only if it makes the same mistake.
        out.extend_from_slice(&((encoded_name.len() + 1) as u16).to_le_bytes());
        out.extend_from_slice(&encoded_name);
        out.push(rtype);

        let data = match self {
            Record::Ptr { target, .. } => encode_name(target),
            Record::Srv { priority, weight, port, target, .. } => {
                let mut d = Vec::new();
                // Big-endian: DNS's own layout, carried through unchanged.
                d.extend_from_slice(&priority.to_be_bytes());
                d.extend_from_slice(&weight.to_be_bytes());
                d.extend_from_slice(&port.to_be_bytes());
                d.extend_from_slice(&encode_name(target));
                d
            }
            Record::Txt { strings, .. } => {
                let mut d = Vec::new();
                for s in strings {
                    d.push(s.len() as u8);
                    d.extend_from_slice(s.as_bytes());
                }
                d
            }
            Record::Other { data, .. } => data.clone(),
        };

        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        // The two bytes upstream calls unknown. Zero in every capture examined, and
        // written as zero rather than omitted -- the field is positional.
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&data);
        out
    }
}

/// Serialise a whole Service Response TLV value from its records.
pub fn encode_records(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.extend_from_slice(&r.encode());
    }
    out
}
