//! The 802.11 management/action header, only as far as AWDL needs it.

use crate::le;

pub const TYPE_MANAGEMENT: u8 = 0;
pub const TYPE_CONTROL: u8 = 1;
pub const TYPE_DATA: u8 = 2;
pub const SUBTYPE_ACTION: u8 = 13;

/// Just the type and subtype, from the first byte.
///
/// Separate from [`Dot11`] because most of the air is control frames -- an ACK is ten
/// bytes and has no address 3 -- so demanding a full 24-byte management header before
/// you can even say what a frame IS makes half a capture look unparseable when it is
/// merely short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameControl {
    pub frame_type: u8,
    pub subtype: u8,
}

impl FrameControl {
    pub fn parse(b: &[u8]) -> Option<FrameControl> {
        let fc = crate::le::u8(b, 0)?;
        if fc & 0b11 != 0 {
            return None; // protocol version must be 0
        }
        Some(FrameControl { frame_type: (fc >> 2) & 0b11, subtype: (fc >> 4) & 0b1111 })
    }

    pub fn is_action(&self) -> bool {
        self.frame_type == TYPE_MANAGEMENT && self.subtype == SUBTYPE_ACTION
    }

    pub fn type_name(&self) -> &'static str {
        match self.frame_type {
            TYPE_MANAGEMENT => "management",
            TYPE_CONTROL => "control",
            TYPE_DATA => "data",
            _ => "reserved",
        }
    }
}

/// A MAC address, kept as bytes so it can be compared and hashed cheaply.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; 6]);

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11 {
    pub frame_type: u8,
    pub subtype: u8,
    pub dst: Mac,
    pub src: Mac,
    pub bssid: Mac,
    /// Offset of the frame body from the start of the 802.11 header.
    pub body_offset: usize,
}

impl Dot11 {
    /// Parse a management-frame header. Returns None for anything too short or for a
    /// protocol version other than 0.
    pub fn parse(b: &[u8]) -> Option<Dot11> {
        let fc = le::u8(b, 0)?;
        if fc & 0b11 != 0 {
            return None; // protocol version must be 0
        }
        let frame_type = (fc >> 2) & 0b11;
        let subtype = (fc >> 4) & 0b1111;

        // Management frames have a fixed 24-byte header: fc(2) dur(2) a1(6) a2(6)
        // a3(6) seq(2). No a4, and no QoS field.
        let mac = |off: usize| -> Option<Mac> {
            Some(Mac(b.get(off..off + 6)?.try_into().ok()?))
        };
        Some(Dot11 {
            frame_type,
            subtype,
            dst: mac(4)?,
            src: mac(10)?,
            bssid: mac(16)?,
            body_offset: 24,
        })
    }

    pub fn is_action(&self) -> bool {
        self.frame_type == TYPE_MANAGEMENT && self.subtype == SUBTYPE_ACTION
    }

    pub fn body<'a>(&self, b: &'a [u8]) -> Option<&'a [u8]> {
        b.get(self.body_offset..)
    }
}

/// Broadcast, which is where 18091 of the 18157 AWDL action frames in `captures/` go.
/// The other 66 are unicast to one peer.
pub const BROADCAST: Mac = Mac([0xff; 6]);

/// Build the 24-byte management header for an AWDL action frame.
///
/// `duration` follows from the destination and is therefore not a parameter: a broadcast
/// frame is never acknowledged and carries 0, a unicast frame carries 48 µs to cover the
/// ACK. Both were measured, and getting it backwards is the kind of thing that works on a
/// forgiving peer and not on a real one.
///
/// `seq` occupies the top 12 bits of the sequence-control field; the low 4 are the
/// fragment number, which is 0 because AWDL action frames are never fragmented.
pub fn management_header(dst: Mac, src: Mac, seq: u16) -> [u8; 24] {
    let mut h = [0u8; 24];
    // Frame control: version 0, type management (0), subtype action (13).
    h[0] = (SUBTYPE_ACTION << 4) | (TYPE_MANAGEMENT << 2);
    h[1] = 0;
    let duration: u16 = if dst == BROADCAST { 0 } else { 48 };
    h[2..4].copy_from_slice(&duration.to_le_bytes());
    h[4..10].copy_from_slice(&dst.0);
    h[10..16].copy_from_slice(&src.0);
    h[16..22].copy_from_slice(&crate::action::BSSID);
    h[22..24].copy_from_slice(&(seq << 4).to_le_bytes());
    h
}
