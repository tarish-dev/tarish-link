//! What a radio can do, and therefore which tier of AWDL it can support.
//!
//! Queried once and then reasoned about. **A missing capability is not an error** — it
//! selects a degraded mode. The alternative, refusing to run on anything less than
//! Apple-grade silicon, would make this unadoptable, which is the opposite of the point.

/// AWDL's social channels. A radio that cannot reach at least one of these cannot do
/// AWDL at all, whatever else it supports.
///
/// Which one applies is regulatory, not a preference: Google's own per-country table
/// maps 263 countries onto exactly these three (6 worldwide default, 44 for the EU and
/// Japan where UNII-3 is restricted, 149 almost everywhere else).
pub const SOCIAL_CHANNELS: [u8; 3] = [6, 44, 149];

/// How well a radio can hold an AWDL cluster. This is the number a vendor should care
/// about, and the one a datasheet should state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// **Receive only.** Can hear AWDL and decode it. Cannot be discovered, cannot
    /// transmit, cannot join a cluster. Useful for analysis and nothing else.
    Observer,

    /// **Software-timed.** Can transmit and switch channels, but the Availability
    /// Window boundaries are met by the host CPU, so synchronisation is only as good as
    /// the scheduler. This is where OWL sits, and it is why OWL's sync is its weak
    /// point. Workable for short-range, low-contention use; degrades under load.
    SoftTimed,

    /// **Hardware-timed.** The radio reads out its MAC TSF and accepts a channel
    /// schedule anchored to it, so window boundaries are met by the MAC rather than by
    /// the CPU. **This is the tier a manufacturer should target.**
    ///
    /// NOTE (finding 88): we have not found this tier on any hardware we can reach. The
    /// Pixel's `wonder` wiphy was assumed to be here — it has `get_mac_tsf` and
    /// `set_channel_schedule_req` vendor-command *symbols* — but a runtime trace of libmosey
    /// shows those are non-functional stubs it never calls: wonder is a soft-MAC and libmosey
    /// times AWDL in software. So `HwTimed` is currently aspirational, and `SoftTimed` with a
    /// low-jitter injection path is what actually interoperates (which libmosey proves).
    HwTimed,
}

/// Precision of the TSF the radio exposes, in microseconds.
///
/// AWDL's Availability Window is 16 TU = 16384 µs. Anything coarser than a few hundred
/// microseconds makes the window boundary meaningless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsfPrecision(pub u32);

#[derive(Debug, Clone)]
pub struct Caps {
    /// Channels the radio can both receive AND transmit on, as channel numbers.
    ///
    /// TRANSMIT is the operative word and the usual disappointment. A radio in a
    /// `country 00` regulatory domain lists 44 and 149 and refuses to transmit on
    /// either, because they are flagged no-IR. A capability probe that only checks
    /// presence reports a radio as capable and then fails in the field.
    pub tx_channels: Vec<u8>,

    /// Monitor mode that **acknowledges** received frames.
    ///
    /// Not a nicety. Without it the peer never sees a link-layer ACK and retransmits
    /// each frame up to seven times, which shows up as a working-but-inexplicably-slow
    /// link rather than as a failure. On Linux this is
    /// `Device supports active monitor (which will ACK incoming frames)`.
    pub active_monitor: bool,

    /// Arbitrary 802.11 frame injection.
    pub injection: bool,

    /// The MAC's TSF counter can be read, and how precisely.
    pub tsf: Option<TsfPrecision>,

    /// The radio accepts a channel schedule anchored to TSF and executes it itself.
    /// This is the single capability that separates [`Tier::HwTimed`] from
    /// [`Tier::SoftTimed`].
    pub scheduled_channels: bool,

    /// Worst-case time to complete a channel switch, microseconds.
    ///
    /// Budget matters: a 16 TU window is 16384 µs, so a 5000 µs switch spends a third
    /// of every slot deaf. Vendors should state this and it should be measured, not
    /// quoted.
    pub channel_switch_us: Option<u32>,

    /// TX rate, preamble, guard interval and MCS can be pinned per frame.
    ///
    /// AWDL sends its sync frames at a fixed low rate for range and predictability;
    /// letting rate control pick means the frame's air time varies, which perturbs the
    /// timing the frame exists to convey.
    pub fixed_tx_rate: bool,

    /// The radio can filter by frame type/subtype and BSSID before waking the host.
    ///
    /// Purely a power optimisation, and the only capability here that is genuinely
    /// optional. Without it the host sees every ACK on the channel — 6287 of 6584
    /// frames in our first capture — and burns CPU discarding them.
    pub rx_filter_offload: bool,
}

impl Caps {
    /// The honest verdict on what this radio can do.
    pub fn tier(&self) -> Tier {
        let can_reach_a_social_channel =
            SOCIAL_CHANNELS.iter().any(|c| self.tx_channels.contains(c));
        if !can_reach_a_social_channel || !self.injection {
            return Tier::Observer;
        }
        if self.scheduled_channels && self.tsf.is_some() {
            return Tier::HwTimed;
        }
        Tier::SoftTimed
    }

    /// Everything preventing this radio from reaching [`Tier::HwTimed`], phrased so it
    /// can be handed to whoever owns the driver.
    ///
    /// Deliberately a list rather than a bool: "not supported" starts an argument,
    /// "these four things are missing" starts a work item.
    pub fn gaps_to_hw_timed(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if !SOCIAL_CHANNELS.iter().any(|c| self.tx_channels.contains(c)) {
            gaps.push("no transmit permission on any AWDL social channel (6, 44, 149)");
        }
        if !self.injection {
            gaps.push("no arbitrary 802.11 frame injection");
        }
        if !self.active_monitor {
            gaps.push("monitor mode does not ACK received frames — peers will retransmit");
        }
        if self.tsf.is_none() {
            gaps.push("MAC TSF cannot be read");
        }
        if !self.scheduled_channels {
            gaps.push("no TSF-anchored channel schedule — windows must be met by the CPU");
        }
        if !self.fixed_tx_rate {
            gaps.push("TX rate cannot be pinned per frame");
        }
        gaps
    }
}
