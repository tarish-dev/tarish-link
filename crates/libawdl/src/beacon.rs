//! Building the frames we put on the air.
//!
//! Everything else in this crate reads AWDL. This writes it, and it is the first thing
//! here that can be *wrong in public* — a malformed frame is not a failed parse, it is
//! noise on a shared channel that other people's devices have to process.
//!
//! # What this deliberately does not do
//!
//! **It does not synchronise to anyone else.** A node that *follows* a master must align
//! its Availability Windows to that master's TSF, and this crate has no TSF read on the
//! hardware it runs on.
//!
//! **A master does not have that problem**, which is the thing worth noticing: the master
//! *is* the reference, so it needs timing that is **self-consistent**, not timing that
//! agrees with somebody else's. A monotonic clock can supply that. So the role that looks
//! harder is the one that is actually available to a radio without TSF support — and the
//! first transmit run bore that out, with two iPhones and a MacBook electing us.
//!
//! What is still missing is precision, not coherence: a host clock has scheduler jitter a
//! MAC timer does not, so our windows will wander by more than Apple's. That is a quality
//! problem to measure, not a correctness one.
//!
//! # PSF and MIF differ by identity, not by size
//!
//! An earlier version of this module guessed that a PSF was a stripped-down timing frame
//! carrying sync and election only. **Measured across 18378 captured frames, that is
//! wrong:**
//!
//! | | mean | tags |
//! |---|---|---|
//! | PSF | 329 B | `4, 5, 18, 6, 24, 12, 7, 17, 21` |
//! | MIF | 626 B | the same, plus `16` and **several** `2` |
//!
//! A PSF carries the whole state set and omits only *who we are* — Arpa — and *what we
//! offer* — Service Response. So the distinction is identity, not weight.
//!
//! Tag order is **not** rigid, which also corrects an earlier claim here. Tag 4 is first
//! in every captured frame; after that the order varies between frames from the same
//! device (`4,5,18,…` and `4,18,32,5,…` both occur). We emit a fixed order because there
//! is no reason not to, not because a peer requires one.
//!
//! We fill ten of the thirteen tags Apple sends. The three missing are 6 — a service hash
//! whose function we cannot compute, and which `libmosey` sends empty while AirDrop works
//! — and 32/33, conditional on a 6 GHz association we do not have. See `docs/GAPS.md`.

use crate::{
    action::{self, Fixed, SUBTYPE_MIF, SUBTYPE_PSF},
    dot11::{management_header, Mac, BROADCAST},
    election::{ElectionParams, ElectionParamsV2, AW_PER_COUNTER_TICK},
    service::{self, Record},
    state::{Arpa, DataPathState, HtCapabilities, Ieee80211Container, Version, ELEM_VHT_CAPABILITIES},
    sync::{ChannelSequence, SyncParams, TU_US},
};

/// One Availability Window in microseconds: 16 TU.
///
/// From the wire, not the paper — `aw_period` reads 16 in all 18157 captured frames.
pub const AW_US: u32 = 16 * TU_US;

/// A metric that loses to any real Apple device: 65, which is what `libmosey` advertises.
///
/// "I am here and I do not want the job." The right default until the schedule we advertise
/// is one we actually keep.
pub const METRIC_DECLINE: u32 = 65;

/// A metric observed to beat real Apple devices, which sat at 510-530.
///
/// **Apple's metrics are not fixed, so this constant goes stale.** In one room on one
/// evening, devices advertised 510, 515, 530, 537 and 539 — and an iPhone at 539 outranked
/// this value the same day it was chosen. Treat it as a starting point and override it when
/// the peers in the room say otherwise; the CLI takes `--metric N` for exactly that.
///
/// **Only correct on a radio that can anchor transmissions to a TSF.** See
/// [`Beacon::metric`] for what happened the first time this was the default.
pub const METRIC_COMPETE: u32 = 530;

/// Everything needed to emit a frame, and the counters that move between frames.
#[derive(Debug, Clone)]
pub struct Beacon {
    /// Our AWDL address. Expected to be locally administered and to rotate; every sender
    /// in `captures/` randomises it, and nothing may treat it as an identity.
    pub addr: [u8; 6],
    /// The host name published in Arpa, without the `.local`.
    pub host: String,
    /// The regional social channel — 6, 44 or 149. See `libawdl_hal::SOCIAL_CHANNELS`.
    pub social_channel: u8,
    /// Our infrastructure association's channel, if we have one. It goes in slot 0 of the
    /// schedule and in Data Path State, and those two must agree.
    pub assoc_channel: Option<u8>,
    /// ISO country code for Data Path State.
    pub country: String,
    /// Our election metric — **how badly we want to be master of the cluster.**
    ///
    /// The default is [`METRIC_DECLINE`], and that is a safety decision rather than a
    /// timidity one. On the first transmit run this defaulted to 530 and **won**: two
    /// iPhones and a MacBook elected our node master, one of them two hops out through the
    /// other. That proved the frames are right and it also anchored three Apple devices'
    /// synchronisation to a node that **does not keep the schedule it advertises**, because
    /// this crate has no TSF to transmit against yet.
    ///
    /// Winning an election you cannot serve is worse than losing it: the cluster follows a
    /// clock that is not a clock. Raise it deliberately, on a radio that can hold time.
    pub metric: u32,
    /// The mDNS instance name we advertise AirDrop under, e.g. `0011223344556677`.
    pub instance: String,
    /// Frames sent, which feeds `tx_counter`.
    pub sent: u16,
    /// Where our tenure counter stood when we took the job. See
    /// [`ElectionParamsV2::self_counter`].
    pub tenure_base: u32,
    /// VHT capability bits. **These describe the radio and must come from it.** The
    /// default is a plausible two-stream 80 MHz claim, which is a placeholder, and
    /// announcing capabilities the hardware lacks invites a peer to use them.
    pub vht: [u8; 12],
    /// HT capability bits, same caveat as [`vht`](Self::vht): they describe the radio, so
    /// the radio is the only correct source. The default mirrors a captured Apple value —
    /// LDPC, 40 MHz, short GI at both widths, two spatial streams.
    pub ht: HtCapabilities,
    /// **Reproduce the timing defect of the first transmit run, on purpose.**
    ///
    /// `aw_remaining` becomes 0 in every frame and `aw_counter` follows the frame count
    /// rather than the clock, which is what the beacon did before finding 35. It exists
    /// only as an experimental control: the question of whether that defect is what made
    /// Apple devices follow us cannot be answered by comparing two runs with different
    /// peers present, and answering it needs the broken condition reproducible on demand.
    ///
    /// **Never set this for anything but an experiment.** It puts a field on the air that
    /// tells every peer our availability window is ending, continuously.
    pub legacy_timing: bool,
}

impl Beacon {
    /// A beacon for a node that is master of a cluster of one.
    pub fn new(addr: [u8; 6], social_channel: u8, country: &str) -> Beacon {
        Beacon {
            addr,
            host: "tarish".to_string(),
            social_channel,
            assoc_channel: None,
            country: country.to_string(),
            metric: METRIC_DECLINE,
            instance: addr.iter().map(|b| format!("{b:02x}")).collect(),
            sent: 0,
            tenure_base: 0,
            vht: [0x32, 0x00, 0x80, 0x03, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0],
            ht: HtCapabilities {
                unknown_0: [0, 0],
                info: 0x006f,
                ampdu_params: 0x17,
                rx_mcs_bitmap: 0xffff,
                trailing: vec![0, 0],
            },
            legacy_timing: false,
        }
    }

    /// The schedule we advertise: Apple's measured shape, four slots of sixteen.
    pub fn schedule(&self) -> ChannelSequence {
        ChannelSequence::apple_shaped(self.social_channel, self.assoc_channel)
    }

    /// Availability Windows elapsed at `now_us`, counted from our own epoch.
    pub fn aws_at(now_us: u64) -> u32 {
        (now_us / u64::from(AW_US)) as u32
    }

    /// Microseconds left in the current Availability Window at `now_us`.
    pub fn aw_remaining_us(now_us: u64) -> u32 {
        AW_US - (now_us % u64::from(AW_US)) as u32
    }

    fn sync(&self, now_us: u64) -> SyncParams {
        SyncParams {
            tx_channel: self.social_channel,
            tx_counter: self.sent,
            master_channel: self.social_channel,
            guard_time: 0,
            // 16 TU, which is what the paper says and what all 18157 captured frames say.
            aw_period: 16,
            action_frame_period: 110,
            // Bit 11 set: the trailing field is absent, which is what every associated
            // Apple device says. See `FLAG_NO_TRAILING`.
            flags: 0x1800,
            aw_ext_length: 16,
            aw_common_length: 16,
            // TU left in this window, from our own clock. **Zero here is a lie**, and it
            // was what this sent on the first transmit run: a joining node reads this to
            // work out where in the schedule it has arrived, and "my window ends now",
            // every frame, forever, is not something it can align to.
            aw_remaining: if self.legacy_timing {
                0
            } else {
                (Self::aw_remaining_us(now_us) / TU_US) as u16
            },
            ext_min: 3,
            ext_max_multicast: 3,
            ext_max_unicast: 3,
            ext_max_af: 3,
            master: self.addr,
            presence_mode: 4,
            reserved_28: 0,
            // Derived from the clock rather than from the frame count. Those only agree
            // if every frame goes out exactly one window apart, which no scheduler
            // guarantees -- and a counter that drifts from its own clock is a counter a
            // follower cannot use.
            aw_counter: if self.legacy_timing {
                // 16 windows per frame, assumed rather than measured -- the original bug.
                self.sent.wrapping_mul(16)
            } else {
                (Self::aws_at(now_us) & 0xffff) as u16
            },
            ap_beacon_alignment_delta: 0,
            channel_sequence: Some(self.schedule()),
            trailing: [0, 0],
        }
    }

    fn tenure(&self, now_us: u64) -> u32 {
        ElectionParamsV2::counter_after(self.tenure_base, Self::aws_at(now_us))
    }

    /// The state every frame carries, PSF and MIF alike.
    ///
    /// This is the measured PSF set minus tag 6, which we cannot fill. A MIF is this plus
    /// identity and services.
    fn state_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        let seq = self.schedule();
        let mut tlvs: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(v) = self.sync(now_us).encode() {
            tlvs.push((4, v));
        }
        tlvs.push((5, ElectionParams::claiming(self.addr, self.metric).encode()));
        if let Some(v) = seq.encode_tag18() {
            tlvs.push((18, v));
        }
        tlvs.push((24, ElectionParamsV2::claiming(self.addr, self.metric, self.tenure(now_us)).encode()));
        tlvs.push((
            12,
            DataPathState::describing(
                self.addr,
                &self.country,
                self.social_channel,
                // A BSSID we do not know is not a BSSID we should invent. Apple zeroes
                // this field even when associated, so zero is what a real device sends.
                self.assoc_channel.map(|c| ([0u8; 6], u16::from(c))),
            )
            .encode(),
        ));
        tlvs.push((7, self.ht.encode()));
        tlvs.push((
            17,
            Ieee80211Container { elements: vec![(ELEM_VHT_CAPABILITIES, self.vht.to_vec())] }
                .encode(),
        ));
        // v3.4, which is what libmosey and OWL announce. Raising it to Apple's 10.0 is a
        // capability claim and a separate decision -- see docs/GAPS.md section 1, where it
        // is also recorded as no longer being the decisive experiment it was thought to be.
        tlvs.push((21, Version { major: 3, minor: 4, device_class: 2 }.encode().to_vec()));
        tlvs
    }

    /// A Periodic Synchronization Frame: state without identity.
    ///
    /// Apple sends these roughly twice as often as MIFs and at about half the size. The
    /// mistake to avoid is sending MIFs at PSF rate — legal, and it wastes a shared
    /// channel.
    pub fn psf_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        self.state_tlvs(now_us)
    }

    /// A Master Indication Frame: the state set, plus who we are and what we offer.
    pub fn mif_tlvs(&self, now_us: u64) -> Vec<(u8, Vec<u8>)> {
        let mut tlvs = self.state_tlvs(now_us);
        tlvs.push((16, Arpa { flags: 3, name: format!("{}.local", self.host) }.encode()));
        tlvs.push((
            2,
            service::encode_records(&[Record::Ptr {
                name: "_airdrop._tcp.local".into(),
                target: format!("{}._airdrop._tcp.local", self.instance),
            }]),
        ));
        tlvs
    }

    /// A complete 802.11 frame, ready for injection.
    ///
    /// `target_tx_time` should come from the radio's TSF. Passing anything else makes the
    /// header's own jitter figure a fiction — see `Fixed::for_tx`.
    pub fn frame(&self, subtype: u8, now_us: u64) -> Vec<u8> {
        let tlvs =
            if subtype == SUBTYPE_MIF { self.mif_tlvs(now_us) } else { self.psf_tlvs(now_us) };
        let mut f = management_header(BROADCAST, Mac(self.addr), self.sent).to_vec();
        // target_tx_time is the same clock, truncated. On a radio that reports TSF this
        // should be the TSF -- see `Fixed::for_tx`.
        f.extend_from_slice(&action::encode_body(
            &Fixed::for_tx(subtype, now_us as u32),
            &tlvs,
        ));
        f
    }

    pub fn mif(&self, now_us: u64) -> Vec<u8> {
        self.frame(SUBTYPE_MIF, now_us)
    }
    pub fn psf(&self, now_us: u64) -> Vec<u8> {
        self.frame(SUBTYPE_PSF, now_us)
    }

    /// The slots we advertise as occupied, in order.
    pub fn advertised_slots(&self) -> Vec<usize> {
        self.schedule()
            .channels
            .iter()
            .enumerate()
            .filter(|(_, c)| **c != 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Microseconds from `now_us` until the start of the next window we advertise.
    ///
    /// **This is what makes the schedule we announce and the schedule we keep the same
    /// thing.** Before this existed the beacon transmitted every sixteen windows — exactly
    /// one cycle — which meant it sat on one arbitrary phase for a whole run, decided by
    /// when the process happened to start, while announcing slots 0, 2, 8 and 10. Measured
    /// on the air it occupied 3 of 16 slots, none of them the advertised ones.
    ///
    /// Needs no TSF and no peer: a master is its own reference, and this aligns us to our
    /// own cycle rather than to anybody else's.
    ///
    /// Returns 0 if we are already inside an advertised window, so a caller loops rather
    /// than sleeping through the window it was waiting for.
    pub fn us_until_next_advertised_window(&self, now_us: u64) -> u64 {
        let slots = self.advertised_slots();
        if slots.is_empty() {
            return u64::from(AW_US);
        }
        let aw = u64::from(AW_US);
        let cycle = aw * 16;
        let pos = now_us % cycle;
        let here = (pos / aw) as usize;
        if slots.contains(&here) {
            return 0;
        }
        // The next advertised slot in this cycle, or the first one in the next.
        let next = slots.iter().copied().find(|s| *s > here).unwrap_or(slots[0] + 16);
        (next as u64) * aw - pos
    }

    /// Count one frame out. Timing no longer lives here — it comes from the clock.
    pub fn advance(&mut self) {
        self.sent = self.sent.wrapping_add(1);
    }

    /// Availability windows per tenure tick, re-exported so a caller pacing this does not
    /// have to reach into `election`.
    pub const AWS_PER_TENURE_TICK: u32 = AW_PER_COUNTER_TICK;
}
