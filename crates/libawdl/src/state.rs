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

    /// The extended block past the flags word, decoded — see finding 49.
    ///
    /// It was carried whole and undecoded because upstream marks several extended fields
    /// "meaning unknown". Three of the four 32-bit values in it are now identified, and
    /// the method was to measure them against a field already known rather than to stare
    /// at the bytes: `master_counter` from tag 24 ticks every 192 Availability Windows,
    /// which is 3.145728 s, so it is a ruler.
    ///
    /// ```text
    ///   tail[0..2]    always 00 00
    ///   tail[2..6]    the master's counter, relayed  -- EQUAL to tag 24's, 100% of 24,915
    ///   tail[6..10]   a millisecond clock            -- 3145.766 ms per tick measured
    ///   tail[10..14]  an Availability Window counter -- exactly 192 per tick
    ///   tail[14..18]  not identified
    /// ```
    fn ext(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.extended_tail.get(at..at + 4)?.try_into().ok()?))
    }

    /// The master's tenure, relayed — the same value tag 24 carries in `master_counter`.
    ///
    /// Equal in **100% of 24,915 frames** carrying both, and equal to the sender's own
    /// `self_counter` in only 56.4% — which is the split you would expect, since those
    /// two coincide exactly when the sender is the master. So this is somebody else's
    /// number and a node that invents one is lying about its master.
    pub fn ext_master_counter(&self) -> Option<u32> {
        self.ext(2)
    }

    /// A free-running millisecond clock.
    ///
    /// Measured against `master_counter` over long spans — short ones measure sampling
    /// jitter, because two frames either side of a tick give one tick and almost no
    /// elapsed time. Median **3145.766 ms per tick** against a theoretical 3145.728, with
    /// six independent sessions inside 0.01%.
    pub fn ext_clock_ms(&self) -> Option<u32> {
        self.ext(6)
    }

    /// An Availability Window counter — one per AW, so 192 per `master_counter` tick.
    ///
    /// **Not** the same counter as tag 4's `aw_counter`: those two are equal in 0% of
    /// frames carrying both, so this one has a different origin. It holds 16-bit values
    /// in a 32-bit field and wraps at 65536.
    ///
    /// One device held `D - 192*B` exactly constant across ~500 frames in seven separate
    /// sessions. Others cluster on two or three adjacent values, which is where in a tick
    /// the frame happened to go out, not drift.
    pub fn ext_aw_counter(&self) -> Option<u32> {
        self.ext(10)
    }

    /// Unidentified. It advances, but at a rate that varies by session — between 1.0 and
    /// 3.2 per `master_counter` tick — so it is not a clock and not a tick counter.
    pub fn ext_unknown_14(&self) -> Option<u32> {
        self.ext(14)
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

    /// Attach the extended block, filled with our own state — finding 49's layout.
    ///
    /// **Why this is opt-in.** libawdl has been elected master repeatedly while sending a
    /// 13-byte tag 12 with no extended block at all, so this is not needed to work. It
    /// exists so the last `u32` of the block can be probed: that value is the only one of
    /// the four finding 49 could not identify, it advances between 1.0 and 3.2 per
    /// `master_counter` tick, and it is neither a clock nor a tick counter.
    ///
    /// `extended_flags` is the one value here we cannot derive. Apple sends
    /// `0x117d | (k << 10)` and it is device-stable, so it looks like a capability word;
    /// non-Apple senders — OWL and `libmosey` — send `0x0000`. **Zero is therefore a value
    /// a real implementation uses**, which makes it the honest default rather than copying
    /// Apple's bits and hoping.
    ///
    /// ```text
    ///   +0..2   extended_flags
    ///   +2..4   zero
    ///   +4..8   master_counter, relayed
    ///   +8..12  a millisecond clock
    ///   +12..16 an Availability Window counter
    ///   +16..20 unidentified
    /// ```
    pub fn with_extended(
        mut self,
        extended_flags: u16,
        master_counter: u32,
        clock_ms: u32,
        aw_counter: u32,
        unidentified: u32,
    ) -> DataPathState {
        self.flags |= flag::EXTENDED;
        self.extended_flags = Some(extended_flags);
        let mut t = Vec::with_capacity(18);
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&master_counter.to_le_bytes());
        t.extend_from_slice(&clock_ms.to_le_bytes());
        t.extend_from_slice(&aw_counter.to_le_bytes());
        t.extend_from_slice(&unidentified.to_le_bytes());
        self.extended_tail = t;
        self
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

// ------------------------------------------------------------------- tag 6 ---

/// Service Parameters (tag 6): a hash of the services this node advertises.
///
/// The field boundaries come from OWL's `awdl_service_params_tlv` — three unnamed bytes, a
/// 16-bit `sui`, then a bitmask — and the captures agree with that split. **The contents
/// are a different matter and are not decoded here**, because a bitmask whose hash
/// function you do not have is not something you can compute, only copy.
///
/// What the captures do show is that the mask is per-service and stable:
///
/// ```text
///   _airdrop         bit 19 set in every frame that advertises it
///   _companion-link  bit 22, in all four
/// ```
///
/// which reads like a Bloom filter over the service name. Twenty observations are not
/// enough to recover the function that produced them, and guessing one would put a claim
/// about our services on the air that we could not check.
///
/// ### Why that does not block anything
///
/// **`libmosey` sends this tag completely empty — `sui` 0, mask 0 — while advertising
/// `_airdrop`, and AirDrop to a Mac works.** Two of our own blazer sessions are in
/// `captures/` doing exactly that, 1611 frames of it. So an Apple device does not require
/// a populated Service Parameters to discover a peer or transfer to one, and the honest
/// thing for a transmitter to send is zeros rather than a hash it invented.
///
/// That is a measurement of what Apple tolerates, not of what Apple means. If a future
/// peer starts filtering on this tag, this is where to look first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceParams {
    /// Bytes 0..3. `00 00 00` in every frame measured.
    pub unknown_0: [u8; 3],
    /// "Service Unique Identifier", per OWL. Varies frame to frame on Apple devices and
    /// is 0 on `libmosey`.
    pub sui: u16,
    /// The service hash. See the type's note: observed, not understood.
    pub bitmask: u32,
    /// Bytes past the mask. Present on the 10- and 11-byte forms and undecoded; the
    /// values look like more mask, which would make the field variable-length.
    pub trailing: Vec<u8>,
}

impl ServiceParams {
    pub const MIN_LEN: usize = 9;

    pub fn parse(v: &[u8]) -> Option<ServiceParams> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(ServiceParams {
            unknown_0: v.get(0..3)?.try_into().ok()?,
            sui: le::u16(v, 3)?,
            bitmask: le::u32(v, 5)?,
            trailing: v.get(9..).unwrap_or(&[]).to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::MIN_LEN + self.trailing.len());
        o.extend_from_slice(&self.unknown_0);
        o.extend_from_slice(&self.sui.to_le_bytes());
        o.extend_from_slice(&self.bitmask.to_le_bytes());
        o.extend_from_slice(&self.trailing);
        o
    }

    /// What `libmosey` sends, and what we should send: nothing.
    ///
    /// Named for what it is rather than called `default()`, so that choosing it is a
    /// decision a reader can see and question rather than a value that arrived by
    /// omission. See the type's note for the evidence that it is accepted.
    pub fn empty() -> ServiceParams {
        ServiceParams { unknown_0: [0; 3], sui: 0, bitmask: 0, trailing: Vec::new() }
    }
}

// ------------------------------------------------------------------- tag 7 ---

/// HT Capabilities (tag 7).
///
/// Like tag 17, most of this is not AWDL's invention: bytes 2..5 are the **HT Capability
/// Information** field and **A-MPDU Parameters** of IEEE 802.11-2020 §9.4.2.55, and the
/// bytes after them begin the Supported MCS Set. Two independent sources agree on that
/// split — OWL's `awdl_ht_capabilities_tlv`, which names `ht_capabilities`,
/// `ampdu_params` and `rx_mcs`, and the values themselves, which decode as sane radios.
///
/// **The tag is not a fixed struct.** It has been seen at 8, 9 and 20 bytes, and the
/// difference is all in the tail. The leading two bytes are `00 00` in every frame in
/// `captures/` and OWL calls them `unknown`; nobody has said what they are.
///
/// ```text
///   00 00  6f 00  1f  ff ff  00 00                Apple, 9 bytes
///   00 00  6f 88  1b  ff ff  00 00 ... 96 00 ...  Apple, 20 bytes
///   00 00  6f 00  17  ff ff  00 00                libmosey, 9 bytes
///          ^^^^^  ^^  ^^^^^
///          info   A-MPDU   MCS 0-15
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtCapabilities {
    /// Bytes 0..2. `00 00` everywhere measured, and unnamed by every source.
    pub unknown_0: [u8; 2],
    /// HT Capability Information, IEEE 802.11-2020 §9.4.2.55.2.
    pub info: u16,
    /// A-MPDU Parameters, §9.4.2.55.3.
    pub ampdu_params: u8,
    /// The first two octets of the Supported MCS Set: one bit per MCS index, 0..15.
    pub rx_mcs_bitmap: u16,
    /// Octets 2.. of the Supported MCS Set — **not a separate field**.
    ///
    /// This was recorded as "length varies by device and is undecoded", and the three
    /// shapes were read as evidence that the tail was a different thing appended to the
    /// named part. It is not: AWDL sends a **truncated Supported MCS Set**, and the octets
    /// present are in the standard order. See [`HtCapabilities::mcs_set`].
    pub trailing: Vec<u8>,
}

impl HtCapabilities {
    pub const MIN_LEN: usize = 7;

    pub fn parse(v: &[u8]) -> Option<HtCapabilities> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(HtCapabilities {
            unknown_0: v.get(0..2)?.try_into().ok()?,
            info: le::u16(v, 2)?,
            ampdu_params: le::u8(v, 4)?,
            rx_mcs_bitmap: le::u16(v, 5)?,
            trailing: v.get(7..).unwrap_or(&[]).to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::MIN_LEN + self.trailing.len());
        o.extend_from_slice(&self.unknown_0);
        o.extend_from_slice(&self.info.to_le_bytes());
        o.push(self.ampdu_params);
        o.extend_from_slice(&self.rx_mcs_bitmap.to_le_bytes());
        o.extend_from_slice(&self.trailing);
        o
    }

    fn bit(&self, n: u32) -> bool {
        self.info & (1 << n) != 0
    }

    /// B0.
    pub fn ldpc(&self) -> bool {
        self.bit(0)
    }
    /// B1: set means 20 and 40 MHz, clear means 20 only.
    pub fn supports_40mhz(&self) -> bool {
        self.bit(1)
    }
    /// B2-B3. 3 means spatial-multiplexing power save is disabled.
    pub fn sm_power_save(&self) -> u16 {
        (self.info >> 2) & 0b11
    }
    /// B4.
    pub fn greenfield(&self) -> bool {
        self.bit(4)
    }
    /// B5.
    pub fn short_gi_20(&self) -> bool {
        self.bit(5)
    }
    /// B6.
    pub fn short_gi_40(&self) -> bool {
        self.bit(6)
    }
    /// B7.
    pub fn tx_stbc(&self) -> bool {
        self.bit(7)
    }
    /// B11: set means 7935 octets, clear means 3839.
    pub fn max_amsdu_octets(&self) -> u16 {
        if self.bit(11) { 7935 } else { 3839 }
    }
    /// B15.
    pub fn lsig_txop_protection(&self) -> bool {
        self.bit(15)
    }

    /// A-MPDU Parameters B0-B1, as the exponent. Length is `2^(13 + exp) - 1` octets.
    pub fn max_ampdu_exponent(&self) -> u8 {
        self.ampdu_params & 0b11
    }
    pub fn max_ampdu_octets(&self) -> u32 {
        (1u32 << (13 + u32::from(self.max_ampdu_exponent()))) - 1
    }

    /// Minimum MPDU start spacing, in microseconds. B2-B4.
    pub fn min_mpdu_start_spacing_us(&self) -> f32 {
        match (self.ampdu_params >> 2) & 0b111 {
            0 => 0.0,
            1 => 0.25,
            2 => 0.5,
            3 => 1.0,
            4 => 2.0,
            5 => 4.0,
            6 => 8.0,
            _ => 16.0,
        }
    }

    /// How many spatial streams the MCS bitmap covers. HT numbers MCS 0-7 for one stream,
    /// 8-15 for two, so a bitmap of 0xffff is two streams.
    pub fn spatial_streams(&self) -> u8 {
        let mut n = 0u8;
        for stream in 0..2u8 {
            let mask = 0xffu16 << (8 * stream);
            if self.rx_mcs_bitmap & mask != 0 {
                n = stream + 1;
            }
        }
        n
    }

    /// The Supported MCS Set, as far as this TLV carries it — IEEE 802.11-2020 §9.4.2.55.4.
    ///
    /// **AWDL TRUNCATES IT**, and that is the whole reason tag 7 has three lengths. The
    /// standard field is 16 octets; Apple sends 4 of them in the 9-byte form and 15 in the
    /// 20-byte one, and libmosey sends 4. Everything present is in the standard order,
    /// which is what makes the long form readable:
    ///
    /// ```text
    ///   octets 0-9   Rx MCS bitmask, one bit per MCS index 0..76
    ///   octets 10-11 Rx Highest Supported Data Rate, B0-B9, in Mb/s
    ///   octet  12    Tx MCS parameters
    ///   octets 13-15 reserved
    /// ```
    ///
    /// It was read the other way for a while — a named part with an undecoded tail
    /// appended — and the three lengths were taken as evidence for that. They are evidence
    /// against it: a truncation explains all three with one structure, and the values land
    /// where the standard puts them. 150 Mb/s at octets 10-11 of Apple's long form is not
    /// a coincidence that a wrong layout would produce.
    pub fn mcs_set(&self) -> Vec<u8> {
        let mut o = self.rx_mcs_bitmap.to_le_bytes().to_vec();
        o.extend_from_slice(&self.trailing);
        o.truncate(16);
        o
    }

    /// Octets 10-11, B0-B9: the highest rate the sender can receive, in Mb/s.
    ///
    /// `None` when the TLV stops before them, which is the common case — only the 20-byte
    /// form carries this.
    pub fn rx_highest_data_rate_mbps(&self) -> Option<u16> {
        let m = self.mcs_set();
        let lo = u16::from(*m.get(10)?);
        let hi = u16::from(*m.get(11)?);
        Some((lo | (hi << 8)) & 0x03ff)
    }

    /// Octet 12 of the MCS set, when present.
    fn tx_mcs_params(&self) -> Option<u8> {
        self.mcs_set().get(12).copied()
    }

    /// Octet 12, B0. Clear means the sender declares no Tx MCS set at all.
    pub fn tx_mcs_set_defined(&self) -> Option<bool> {
        Some(self.tx_mcs_params()? & 0b1 != 0)
    }

    /// Octet 12, B1. Set means the Tx and Rx MCS sets differ, and B2-B3 then matter.
    pub fn tx_rx_mcs_set_not_equal(&self) -> Option<bool> {
        Some(self.tx_mcs_params()? & 0b10 != 0)
    }

    /// Octet 12, B2-B3. The field holds streams minus one, so it is returned as a count.
    pub fn tx_max_spatial_streams(&self) -> Option<u8> {
        Some(((self.tx_mcs_params()? >> 2) & 0b11) + 1)
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

/// The body of a VHT Capabilities element, decoded per IEEE 802.11-2020 §9.4.2.157.
///
/// Unlike almost everything else in this crate, **this one is not reverse engineered** —
/// it is a published format, and AWDL carries it verbatim rather than inventing its own.
/// That is worth stating because it changes what the bytes are for: they describe the
/// radio, so on transmit they must come from the radio and not from a table copied out of
/// an Apple frame. Announcing capabilities the hardware does not have invites a peer to
/// use them.
///
/// The captured Apple value decodes as a two-stream 80 MHz phone:
///
/// ```text
///   32 00 80 03   max MPDU 11454, 20/40/80 MHz, Rx LDPC, short GI 80, A-MPDU exp 7
///   fa ff 00 00   Rx: MCS 0-9 on 2 spatial streams, none beyond
///   fa ff 00 00   Tx: the same
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtCapabilities {
    pub info: u32,
    pub rx_mcs_map: u16,
    pub rx_highest_mbps: u16,
    pub tx_mcs_map: u16,
    pub tx_highest_mbps: u16,
}

/// What a two-bit entry in a VHT-MCS map means for one spatial stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McsSupport {
    Upto7,
    Upto8,
    Upto9,
    NotSupported,
}

impl VhtCapabilities {
    pub const LEN: usize = 12;

    pub fn parse(v: &[u8]) -> Option<VhtCapabilities> {
        if v.len() < Self::LEN {
            return None;
        }
        Some(VhtCapabilities {
            info: le::u32(v, 0)?,
            rx_mcs_map: le::u16(v, 4)?,
            rx_highest_mbps: le::u16(v, 6)?,
            tx_mcs_map: le::u16(v, 8)?,
            tx_highest_mbps: le::u16(v, 10)?,
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut o = [0u8; Self::LEN];
        o[0..4].copy_from_slice(&self.info.to_le_bytes());
        o[4..6].copy_from_slice(&self.rx_mcs_map.to_le_bytes());
        o[6..8].copy_from_slice(&self.rx_highest_mbps.to_le_bytes());
        o[8..10].copy_from_slice(&self.tx_mcs_map.to_le_bytes());
        o[10..12].copy_from_slice(&self.tx_highest_mbps.to_le_bytes());
        o
    }

    fn bits(&self, lo: u32, n: u32) -> u32 {
        (self.info >> lo) & ((1 << n) - 1)
    }

    /// Maximum MPDU length in octets. B0-B1.
    pub fn max_mpdu_octets(&self) -> Option<u32> {
        match self.bits(0, 2) {
            0 => Some(3895),
            1 => Some(7991),
            2 => Some(11454),
            _ => None, // 3 is reserved
        }
    }

    /// Supported channel widths, as text. B2-B3.
    ///
    /// Note what this does NOT say: 80 MHz support is implied by the element existing at
    /// all, so value 0 means "20, 40 and 80", not "20 and 40".
    pub fn channel_widths(&self) -> &'static str {
        match self.bits(2, 2) {
            0 => "20/40/80",
            1 => "20/40/80/160",
            2 => "20/40/80/160/80+80",
            _ => "reserved",
        }
    }

    /// B4.
    pub fn rx_ldpc(&self) -> bool {
        self.bits(4, 1) == 1
    }
    /// B5.
    pub fn short_gi_80(&self) -> bool {
        self.bits(5, 1) == 1
    }
    /// B6.
    pub fn short_gi_160(&self) -> bool {
        self.bits(6, 1) == 1
    }
    /// B7.
    pub fn tx_stbc(&self) -> bool {
        self.bits(7, 1) == 1
    }
    /// B8-B10: how many spatial streams STBC reception is supported on.
    pub fn rx_stbc_streams(&self) -> u32 {
        self.bits(8, 3)
    }
    /// B11.
    pub fn su_beamformer(&self) -> bool {
        self.bits(11, 1) == 1
    }
    /// B12.
    pub fn su_beamformee(&self) -> bool {
        self.bits(12, 1) == 1
    }
    /// B19.
    pub fn mu_beamformer(&self) -> bool {
        self.bits(19, 1) == 1
    }
    /// B20.
    pub fn mu_beamformee(&self) -> bool {
        self.bits(20, 1) == 1
    }
    /// B23-B25, as the exponent itself. The length is `2^(13 + exp) - 1` octets.
    pub fn max_ampdu_exponent(&self) -> u32 {
        self.bits(23, 3)
    }
    pub fn max_ampdu_octets(&self) -> u32 {
        (1u32 << (13 + self.max_ampdu_exponent())) - 1
    }

    /// What one spatial stream supports, from a VHT-MCS map. `stream` is 1-based.
    pub fn mcs_for(map: u16, stream: u8) -> McsSupport {
        if !(1..=8).contains(&stream) {
            return McsSupport::NotSupported;
        }
        match (map >> (2 * (stream - 1))) & 0b11 {
            0 => McsSupport::Upto7,
            1 => McsSupport::Upto8,
            2 => McsSupport::Upto9,
            _ => McsSupport::NotSupported,
        }
    }

    /// How many spatial streams the map actually supports.
    pub fn spatial_streams(map: u16) -> u8 {
        (1..=8u8).filter(|s| Self::mcs_for(map, *s) != McsSupport::NotSupported).count() as u8
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
    /// **The device's own 6 GHz infrastructure channel.**
    ///
    /// Proven rather than inferred, on 2026-09-12: the sender was identified as a
    /// particular MacBook by matching the frame's source against that machine's own
    /// `awdl0` address, and `system_profiler` on that machine reported "Channel: 53
    /// (6GHz, 160MHz)" while its frames carried channel 53, operating class 134. The
    /// device's own operating system and its AWDL frames agree.
    pub channel: ClassChannel,
    /// Everything after the class/channel pair, kept raw.
    ///
    /// Bytes 6..9 were `04 08 02` in every frame from every device. Bytes 9..11 move
    /// within a single device in a single capture — `c1 c0`, `83 8a`, `01 00` from one
    /// Mac in 90 seconds — so they are live state, not a constant. Bytes 11..13 have
    /// always been zero. None of it is decoded.
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
/// **The first pair is the device's own 6 GHz association and is empty when it has none;
/// the second is populated either way.** Measured across three different channels — 17,
/// 53 and 85 — from five devices:
///
/// ```text
///   01 00 00 00 | 35 86 | 01 | 35 86 | 00 | 00 00 00 00   macOS, OS reports 6 GHz ch 53
///   01 00 00 00 | 00 00 | 01 | 11 86 | 00 | 00 00 00 00   iOS, no 6 GHz association
///   01 00 00 00 | 55 86 | 01 | 55 86 | 27 | 00 00 00 00   ch 85, and byte 9 is 0x27
/// ```
///
/// The field boundaries are established by variation, not by assumption: bytes 4..6 and
/// 7..9 track the channel and go to `00 00` when there is none, while `01 00 00 00`, the
/// `01` separator and the trailing four zeros did not move once across those three
/// channels. Byte 9 was `0x27` on exactly one device.
///
/// **Why these tags exist at all**: on a 6 GHz association, Data Path State reports
/// `infra_channel` as **0** — verified on the MacBook above, which was associated and
/// still published zero — and the channel sequence cannot express 6 GHz either (finding
/// 17). So this tag is the only place a 6 GHz association is visible.
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
