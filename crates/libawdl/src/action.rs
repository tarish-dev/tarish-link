//! The AWDL action frame: how you tell an AWDL frame from every other frame in the air.
//!
//! AWDL rides inside an 802.11 **vendor-specific action frame**. Four things have to
//! line up, and checking fewer than all four is how a capture ends up full of other
//! vendors' traffic:
//!
//! ```text
//!   802.11 type/subtype   management / action        (0 / 13)
//!   category              0x7f  vendor specific
//!   OUI                   00:17:f2                   Apple
//!   awdl type             0x08                       Apple's own sub-protocol tag
//! ```
//!
//! The OUI alone is not enough. Apple puts several protocols behind `00:17:f2`, and
//! the type byte after it is what says AWDL rather than something else.

use crate::le;
use crate::tlv::Tlvs;

/// IEEE 802.11 action category for vendor-specific frames.
pub const CATEGORY_VENDOR_SPECIFIC: u8 = 0x7f;

/// Apple's OUI, as it appears on the wire.
pub const OUI_APPLE: [u8; 3] = [0x00, 0x17, 0xf2];

/// The byte after the OUI that distinguishes AWDL from Apple's other vendor frames.
pub const AWDL_TYPE: u8 = 0x08;

/// The fixed BSSID every AWDL action frame carries, on every device, in every capture.
///
/// 18157 frames in `captures/`, one value. It is not a real BSS — nothing associates to
/// it — but a receiver filters on it, so a frame without it is a frame nobody reads.
pub const BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

/// The action-frame header version: 0x10, meaning 1.0, in all 18157 frames.
///
/// **This is not the version in tag 21.** That one reads 3.4 from `libmosey` and OWL and
/// 10.0 from Apple, and is the subject of §1 of `docs/GAPS.md`. This byte does not vary at
/// all — not between vendors and not between Apple's own major releases — so the two count
/// different things, and changing one is not changing the other.
pub const HEADER_VERSION: u8 = 0x10;

/// Periodic Synchronization Frame — sent frequently, carries timing.
pub const SUBTYPE_PSF: u8 = 0;
/// Master Indication Frame — sent by the elected master, carries the full parameter set.
pub const SUBTYPE_MIF: u8 = 3;

pub fn subtype_name(s: u8) -> &'static str {
    match s {
        SUBTYPE_PSF => "PSF",
        SUBTYPE_MIF => "MIF",
        _ => "unknown",
    }
}

/// AWDL's 12-byte fixed header, which precedes the TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixed {
    pub version_major: u8,
    pub version_minor: u8,
    pub subtype: u8,
    /// Time the PHY actually started transmitting, in TU-derived units.
    pub phy_tx_time: u32,
    /// Time the sender *intended* to transmit.
    pub target_tx_time: u32,
    /// Byte 7, reserved. Zero in all 18157 frames measured; carried so that a parse and
    /// re-encode is exact rather than exact-as-long-as-the-measurement-holds.
    pub reserved_7: u8,
}

impl Fixed {
    /// How late the frame went out.
    ///
    /// This is the single most interesting number in the header for synchronisation
    /// work: it is the sender telling you its own transmit jitter, and it is what any
    /// receiver has to compensate for to stay in the cluster. Wraps like the counters
    /// it is derived from, hence the wrapping subtraction.
    pub fn tx_delay(&self) -> u32 {
        self.phy_tx_time.wrapping_sub(self.target_tx_time)
    }

    /// The 16 bytes before the TLVs: category, OUI, type, and the 12-byte fixed block.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.push(CATEGORY_VENDOR_SPECIFIC);
        out.extend_from_slice(&OUI_APPLE);
        out.push(AWDL_TYPE);
        // Nibbles, not a byte: 0x10 is 1.0. Writing 10 here says 0.10 and no receiver
        // would recognise the frame.
        out.push((self.version_major << 4) | (self.version_minor & 0x0f));
        out.push(self.subtype);
        out.push(self.reserved_7);
        out.extend_from_slice(&self.phy_tx_time.to_le_bytes());
        out.extend_from_slice(&self.target_tx_time.to_le_bytes());
        out
    }

    /// A header for a frame we are about to send.
    ///
    /// `phy_tx_time` is left equal to `target_tx_time`, which claims zero transmit jitter.
    /// **That claim is only true if the caller sets it from the radio.** On hardware that
    /// cannot report when the PHY actually started — which is most of it, and the reason
    /// `libawdl-hal` grades radios into tiers — the honest value is the one we intended,
    /// and peers treat the difference as our clock error. It is a field to fill in, not a
    /// field to forget.
    pub fn for_tx(subtype: u8, target_tx_time: u32) -> Fixed {
        Fixed {
            version_major: HEADER_VERSION >> 4,
            version_minor: HEADER_VERSION & 0x0f,
            subtype,
            reserved_7: 0,
            phy_tx_time: target_tx_time,
            target_tx_time,
        }
    }
}

/// Assemble an AWDL action frame body: the fixed header, then the TLVs in order.
///
/// Order is the caller's business and it is not cosmetic — a receiver reads the tags in
/// the order they arrive, and Apple's own frames put Synchronization Parameters first.
pub fn encode_body(fixed: &Fixed, tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = fixed.encode();
    for (tag, value) in tlvs {
        out.push(*tag);
        // Long form: a two-byte little-endian length. Action frames never use the short
        // form, whatever the data path does.
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionFrame<'a> {
    pub fixed: Fixed,
    /// The TLV region, unparsed. Iterate it with `tlvs()`.
    pub tagged: &'a [u8],
}

impl<'a> ActionFrame<'a> {
    /// Parse an AWDL action frame from an 802.11 **frame body** (i.e. after the 24-byte
    /// management header).
    ///
    /// Returns None for any frame that is not AWDL. That is the common case by a wide
    /// margin — most of the air is not AWDL — so this is a filter, not an error path.
    pub fn parse(body: &'a [u8]) -> Option<ActionFrame<'a>> {
        if le::u8(body, 0)? != CATEGORY_VENDOR_SPECIFIC {
            return None;
        }
        if body.get(1..4)? != OUI_APPLE {
            return None;
        }
        // The AWDL fixed header begins at the type byte, which is also the first byte
        // of the 12-byte block Wireshark labels "fixed parameters".
        let t = le::u8(body, 4)?;
        if t != AWDL_TYPE {
            return None;
        }
        let version = le::u8(body, 5)?;
        let fixed = Fixed {
            // Version is a packed pair of nibbles: 0x10 is 1.0, not 16.
            version_major: version >> 4,
            version_minor: version & 0x0f,
            subtype: le::u8(body, 6)?,
            reserved_7: le::u8(body, 7)?,
            phy_tx_time: le::u32(body, 8)?,
            target_tx_time: le::u32(body, 12)?,
        };
        Some(ActionFrame { fixed, tagged: body.get(16..)? })
    }

    pub fn tlvs(&self) -> Tlvs<'a> {
        Tlvs::new(self.tagged)
    }
}
