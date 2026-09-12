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

    /// Serialise back to the wire: two bytes, packed nibbles then the device class.
    pub fn encode(&self) -> [u8; 2] {
        [(self.major << 4) | (self.minor & 0x0f), self.device_class]
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
    /// Serialise back to the wire: the flags byte, then the name in the compressed DNS
    /// encoding shared with Service Response.
    ///
    /// Compression is not an optimisation here. The captured Apple values end in a
    /// `0xc00c` pointer, so a builder that spells `local` out produces a longer tag that
    /// still parses and that no Apple device would have sent.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.name.len() + 2);
        out.push(self.flags);
        out.extend_from_slice(&crate::service::encode_name(&self.name));
        out
    }

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
    /// The UMI options blob, kept whole. Its contents are not decoded, but it sits
    /// *between* other fields, so a builder that drops it shifts everything after it.
    pub umi_options: Option<Vec<u8>>,
    pub extended_flags: Option<u16>,
    /// Whatever follows the extended flags word. Undecoded upstream, carried so that a
    /// parse and rebuild is exact.
    pub extended_tail: Vec<u8>,
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
            s.umi_options = v.get(off + 2..off + 2 + n).map(|b| b.to_vec());
            off += 2 + n;
        }
        if flags & flag::EXTENDED != 0 {
            s.extended_flags = le::u16(v, off);
            s.extended_tail = v.get(off + 2..).unwrap_or(&[]).to_vec();
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

    /// Serialise back to the wire.
    ///
    /// **The order here is the wire order, not the bit order**, and it has to match
    /// `parse` exactly — country and social channel precede the infrastructure fields
    /// despite having higher bit numbers. Writing them in numeric order produces a tag
    /// that parses without error into entirely different values.
    ///
    /// The bitmap is taken from `flags` rather than recomputed from which options are
    /// `Some`, so a tag that arrived claiming a field it did not carry re-encodes as it
    /// arrived instead of being quietly corrected.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.flags.to_le_bytes());
        if self.flags & flag::COUNTRY != 0 {
            let c = self.country.clone().unwrap_or_default();
            let mut b = c.into_bytes();
            b.resize(3, 0);
            out.extend_from_slice(&b);
        }
        if self.flags & flag::SOCIAL_CHANNEL != 0 {
            out.extend_from_slice(&self.social_channel_raw.unwrap_or(0).to_le_bytes());
        }
        if self.flags & flag::INFRA_BSSID != 0 {
            out.extend_from_slice(&self.infra_bssid.unwrap_or_default());
            out.extend_from_slice(&self.infra_channel.unwrap_or(0).to_le_bytes());
        }
        if self.flags & flag::INFRA_ADDRESS != 0 {
            out.extend_from_slice(&self.infra_address.unwrap_or_default());
        }
        if self.flags & flag::AWDL_ADDRESS != 0 {
            out.extend_from_slice(&self.awdl_address.unwrap_or_default());
        }
        if self.flags & flag::UMI != 0 {
            out.extend_from_slice(&self.umi.unwrap_or(0).to_le_bytes());
        }
        if self.flags & flag::UMI_OPTIONS != 0 {
            let o = self.umi_options.clone().unwrap_or_default();
            out.extend_from_slice(&(o.len() as u16).to_le_bytes());
            out.extend_from_slice(&o);
        }
        if self.flags & flag::EXTENDED != 0 {
            out.extend_from_slice(&self.extended_flags.unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&self.extended_tail);
        }
        out
    }

    /// What this device is: its AWDL address, its region, its social channel, and the
    /// access point it is associated to if there is one.
    ///
    /// `infra` is the AP's BSSID and channel. Supplying it sets [`flag::INFRA_BSSID`],
    /// which is what tells a peer we are associated at all — and it is the same channel
    /// that belongs in slot 0 of the schedule. The two are separate statements of one
    /// fact, and a peer that finds them disagreeing has no way to tell which is right.
    pub fn describing(
        awdl_address: [u8; 6],
        country: &str,
        social_channel: u8,
        infra: Option<([u8; 6], u16)>,
    ) -> DataPathState {
        let mut flags = flag::COUNTRY | flag::SOCIAL_CHANNEL | flag::AWDL_ADDRESS;
        if infra.is_some() {
            flags |= flag::INFRA_BSSID;
        }
        DataPathState {
            flags,
            country: Some(country.to_string()),
            social_channel_raw: Some(u16::from(social_channel)),
            infra_bssid: infra.map(|(b, _)| b),
            infra_channel: infra.map(|(_, c)| c),
            awdl_address: Some(awdl_address),
            ..Default::default()
        }
    }
}

// ------------------------------------------------------------------ tag 17 ---

/// IEEE 802.11 Container (tag 17): standard 802.11 information elements, verbatim.
///
/// AWDL does not invent a capability format — it carries the ones 802.11 already defines.
/// The captured values hold a single element `0xbf` (VHT Capabilities) with a 12-byte body,
/// which is exactly what the standard specifies: four bytes of capability info and eight of
/// the supported VHT-MCS and NSS set.
///
/// The elements are kept as `(id, body)` pairs rather than decoded. The bits inside them
/// describe the radio, so the only correct source for them is the radio — `libawdl-hal`,
/// not a table in here. Carrying them opaquely is what lets a HAL supply its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ieee80211Container {
    pub elements: Vec<(u8, Vec<u8>)>,
}

/// Element ID for VHT Capabilities, the one observed in every captured container.
pub const ELEM_VHT_CAPABILITIES: u8 = 0xbf;

impl Ieee80211Container {
    /// Walk the element list. Stops rather than guessing when a length runs past the end,
    /// for the same reason the TLV iterator does: a truncated capture and a malformed
    /// frame look identical, and trimming one to fit invents data.
    pub fn parse(v: &[u8]) -> Option<Ieee80211Container> {
        let mut elements = Vec::new();
        let mut off = 0usize;
        while off + 2 <= v.len() {
            let id = v[off];
            let len = usize::from(v[off + 1]);
            let body = v.get(off + 2..off + 2 + len)?;
            elements.push((id, body.to_vec()));
            off += 2 + len;
        }
        // A container with bytes left over is not one we understood.
        if off != v.len() {
            return None;
        }
        Some(Ieee80211Container { elements })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, body) in &self.elements {
            out.push(*id);
            out.push(body.len() as u8);
            out.extend_from_slice(body);
        }
        out
    }

    /// The VHT Capabilities element, if the container carries one.
    pub fn vht_capabilities(&self) -> Option<&[u8]> {
        self.elements.iter().find(|(id, _)| *id == ELEM_VHT_CAPABILITIES).map(|(_, b)| b.as_slice())
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
