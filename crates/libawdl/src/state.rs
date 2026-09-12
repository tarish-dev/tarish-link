//! Data Path State (12), Version (21) and Arpa (16).
//!
//! Data Path State is the interesting one: it carries **the infrastructure BSSID and
//! channel the device is associated to**, which is an entirely independent source for the
//! association that finding 18 established from slot 0 of the channel sequence. Two
//! unrelated fields agreeing is much stronger evidence than either alone.

use crate::le;
use crate::service::decode_name;

// ------------------------------------------------------------------ tag 21 ---

/// Which Apple OS the peer runs. Values as Wireshark names them.
pub fn device_class_name(c: u8) -> &'static str {
    match c {
        1 => "macOS",
        2 => "iOS",
        4 => "watchOS",
        8 => "tvOS",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub device_class: u8,
}

impl Version {
    pub fn parse(v: &[u8]) -> Option<Version> {
        let ver = le::u8(v, 0)?;
        Some(Version {
            // Packed nibbles, as in the action-frame header: 0x10 is 1.0, not 16.
            major: ver >> 4,
            minor: ver & 0x0f,
            device_class: le::u8(v, 1)?,
        })
    }

    pub fn class_name(&self) -> &'static str {
        device_class_name(self.device_class)
    }
}

// ------------------------------------------------------------------ tag 16 ---

/// Arpa — the device's host name, in the compressed DNS encoding.
///
/// This is where `iPhone (2)` comes from: a name a person recognises, as opposed to the
/// 12-hex AirDrop instance identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arpa {
    pub flags: u8,
    pub name: String,
}

impl Arpa {
    pub fn parse(v: &[u8]) -> Option<Arpa> {
        let flags = le::u8(v, 0)?;
        let rest = v.get(1..)?;
        let (name, _) = decode_name(rest, rest.len())?;
        Some(Arpa { flags, name })
    }
}

// ------------------------------------------------------------------ tag 12 ---

/// Which optional fields are present. The tag is a bitmap followed by only the fields
/// the bitmap claims, so **reading it as a fixed struct produces garbage** — every
/// offset depends on how many earlier bits were set.
pub mod flag {
    /// Infrastructure BSSID (6) + channel (2) follow.
    pub const INFRA_BSSID: u16 = 0x0001;
    /// Infrastructure MAC address (6) follows.
    pub const INFRA_ADDRESS: u16 = 0x0002;
    /// AWDL address (6) follows.
    pub const AWDL_ADDRESS: u16 = 0x0004;
    /// UMI (2) follows.
    pub const UMI: u16 = 0x0010;
    /// Country code (3 ASCII) follows.
    pub const COUNTRY: u16 = 0x0100;
    /// Social channel or channel map (2) follows.
    pub const SOCIAL_CHANNEL: u16 = 0x0200;
    /// UMI options: length (2) then that many bytes.
    pub const UMI_OPTIONS: u16 = 0x1000;
    /// Extended flags (2) and their own optional fields.
    pub const EXTENDED: u16 = 0x8000;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataPathState {
    pub flags: u16,
    /// Regulatory country, 3 ASCII bytes.
    pub country: Option<String>,
    /// Either one social channel, or a bitmap of the three. The distinction is a
    /// heuristic upstream flags as unverified, so both are kept raw.
    pub social_channel_raw: Option<u16>,
    /// **The access point this device is associated to.** Present only when
    /// [`flag::INFRA_BSSID`] is set, which is itself the signal that it is associated.
    pub infra_bssid: Option<[u8; 6]>,
    /// The AP's channel — independent confirmation of the association slot.
    pub infra_channel: Option<u16>,
    pub infra_address: Option<[u8; 6]>,
    pub awdl_address: Option<[u8; 6]>,
    pub umi: Option<u16>,
    pub extended_flags: Option<u16>,
}

impl DataPathState {
    pub fn parse(v: &[u8]) -> Option<DataPathState> {
        let flags = le::u16(v, 0)?;
        let mut s = DataPathState { flags, ..Default::default() };
        let mut off = 2usize;

        // ORDER IS NOT THE BIT ORDER. Country (0x0100) and social channel (0x0200) come
        // before the infrastructure fields (0x0001, 0x0002) on the wire, so iterating
        // the bits numerically reads every later field from the wrong offset.
        if flags & flag::COUNTRY != 0 {
            let c = v.get(off..off + 3)?;
            s.country = Some(String::from_utf8_lossy(c).trim_end_matches('\0').to_string());
            off += 3;
        }
        if flags & flag::SOCIAL_CHANNEL != 0 {
            s.social_channel_raw = le::u16(v, off);
            off += 2;
        }
        if flags & flag::INFRA_BSSID != 0 {
            s.infra_bssid = v.get(off..off + 6)?.try_into().ok();
            s.infra_channel = le::u16(v, off + 6);
            off += 8;
        }
        if flags & flag::INFRA_ADDRESS != 0 {
            s.infra_address = v.get(off..off + 6)?.try_into().ok();
            off += 6;
        }
        if flags & flag::AWDL_ADDRESS != 0 {
            s.awdl_address = v.get(off..off + 6)?.try_into().ok();
            off += 6;
        }
        if flags & flag::UMI != 0 {
            s.umi = le::u16(v, off);
            off += 2;
        }
        if flags & flag::UMI_OPTIONS != 0 {
            let n = le::u16(v, off)? as usize;
            off += 2 + n;
        }
        if flags & flag::EXTENDED != 0 {
            s.extended_flags = le::u16(v, off);
            // The extended fields beyond the flags word are left undecoded: upstream
            // marks several of them "meaning unknown", and a speculative name is worse
            // than none.
        }
        Some(s)
    }

    /// Whether this device says it is associated to an access point.
    pub fn is_associated(&self) -> bool {
        self.flags & flag::INFRA_BSSID != 0
    }
}

// -------------------------------------------------------------- tags 32, 33 ---
//
// These two appear in no published table. Wireshark's tag enumeration ends at 24 and
// reports them unnamed; the 2018 paper does not mention them. What follows was derived
// from captures, and the reasoning is given so it can be challenged.

/// 802.11 operating classes for 6 GHz. 134 is 6 GHz at 160 MHz.
pub const OPCLASS_6GHZ: std::ops::RangeInclusive<u8> = 131..=136;

pub fn opclass_band(c: u8) -> &'static str {
    match c {
        81 | 83 | 84 => "2.4 GHz",
        115..=130 => "5 GHz",
        131..=136 => "6 GHz",
        _ => "?",
    }
}

/// A channel with the operating class that gives it meaning.
///
/// A bare channel number is ambiguous across bands — 53 exists in 6 GHz and nowhere
/// useful otherwise — so the class travels with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassChannel {
    pub channel: u8,
    pub opclass: u8,
}

impl ClassChannel {
    pub fn band(&self) -> &'static str {
        opclass_band(self.opclass)
    }
    pub fn is_6ghz(&self) -> bool {
        OPCLASS_6GHZ.contains(&self.opclass)
    }
}

/// Tag 32 — a single class/channel, with surrounding bytes not yet understood.
///
/// **Evidence for the reading.** Across 18 captures every value has this shape:
///
/// ```text
///   00 00 | 86 00 | CC 00 | 04 08 02 | XX XX | 00 00
///           ^^^^^   ^^^^^
///           opclass channel, both little-endian u16
/// ```
///
/// The class byte is **always 0x86 = 134**, which is 802.11's operating class for 6 GHz at
/// 160 MHz. The channel byte takes 0x35 (53), 0x55 (85) and 0x11 (17) — all valid 6 GHz
/// channel numbers, and 53 is exactly what the Mac in these captures reports for itself
/// (`Channel: 53 (6GHz, 160MHz)`).
///
/// `04 08 02` is constant and unexplained. The two bytes before the trailing zeros vary
/// (`83 8a`, `01 00`, `c1 c0`, `c0 c0`, `db da`) and are left undecoded rather than named
/// speculatively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SixGhzInfo {
    pub channel: ClassChannel,
    /// Everything after the class/channel pair, kept raw.
    pub trailing: Vec<u8>,
}

impl SixGhzInfo {
    pub const LEN: usize = 13;

    pub fn parse(v: &[u8]) -> Option<SixGhzInfo> {
        if v.len() < Self::LEN {
            return None;
        }
        let opclass = le::u16(v, 2)? as u8;
        let channel = le::u16(v, 4)? as u8;
        Some(SixGhzInfo {
            channel: ClassChannel { channel, opclass },
            trailing: v.get(6..)?.to_vec(),
        })
    }
}

/// Tag 33 — class/channel pairs, in the same byte order the channel sequence uses.
///
/// ```text
///   01 00 00 00 | CC OO | 01 | CC OO | XX | 00 00 00 00
///                 ^^^^^        ^^^^^
///                 channel then opclass, as OpClass encoding does it
/// ```
///
/// Both pairs have been identical in every capture, which is why it reads as one channel
/// stated twice rather than two different ones. A value of `00 00` for the first pair with
/// `11 86` for the second has also been seen, so they are not required to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SixGhzChannels {
    pub first: Option<ClassChannel>,
    pub second: Option<ClassChannel>,
    pub trailing: Vec<u8>,
}

impl SixGhzChannels {
    pub const LEN: usize = 14;

    pub fn parse(v: &[u8]) -> Option<SixGhzChannels> {
        if v.len() < Self::LEN {
            return None;
        }
        // Channel first, class second -- the opposite of tag 32, and the same as the
        // channel sequence's OpClass form. Reading either as the other yields a
        // plausible channel number and the wrong band.
        let pair = |off: usize| -> Option<ClassChannel> {
            let channel = le::u8(v, off)?;
            let opclass = le::u8(v, off + 1)?;
            if channel == 0 && opclass == 0 {
                return None;
            }
            Some(ClassChannel { channel, opclass })
        };
        Some(SixGhzChannels {
            first: pair(4),
            second: pair(7),
            trailing: v.get(9..)?.to_vec(),
        })
    }
}
