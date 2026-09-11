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
