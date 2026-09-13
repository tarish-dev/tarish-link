//! Recovering the cluster's clock from the frames it sends.
//!
//! # The realisation this is built on
//!
//! A node that wants to join an AWDL cluster has to know **when the cluster's Availability
//! Windows start**. The obvious way is the radio's TSF, and the obvious problem is that the
//! adapter this project runs on reports no TSFT at all — 0 of 801 frames in every capture in
//! `captures/`.
//!
//! It does not need to. **The peers tell us.** Synchronization Parameters carries
//! `aw_remaining`, the TU left in the sender's current window, and `aw_counter`, which
//! window it is. A frame that arrives at our time `t` saying "6 TU left in window 4291"
//! places that window's boundary at `t + 6 TU` on *our* clock, and identifies it.
//!
//! That is what the field is for. This crate's own parser has said so since the first week:
//! *"the field a joining node uses to work out where in the schedule it has arrived"*. It
//! took until the transmitter existed to notice it was the answer to the timing problem
//! rather than a curiosity.
//!
//! # What this is not
//!
//! It is not as good as a MAC TSF. Every estimate carries the error between when the frame
//! was on the air and when the host timestamped it — for a USB adapter, milliseconds of
//! jitter against a 16384 µs window. So this **tracks** rather than **locks**: it takes many
//! observations and keeps the median, and it reports its own spread so a caller can tell a
//! usable estimate from a guess.

use crate::election::ElectionParamsV2;
use crate::sync::{SyncParams, TU_US};

/// Availability Window, microseconds. 16 TU, as every captured frame agrees.
pub const AW_US: u64 = 16 * TU_US as u64;

/// How many Availability Windows make one channel-sequence slot.
///
/// **A slot is an EXTENDED Availability Window, not a single one**, and this project had it
/// wrong until OWL's `schedule.c` was read properly: its slot index is
/// `awdl_sync_current_eaw(...) % AWDL_CHANSEQ_LENGTH`, where an EAW is
/// `presence_mode * aw_period`.
///
/// Settled from the frames themselves rather than from timing, which is what makes it
/// certain. Each frame carries both its `aw_counter` and the schedule its sender
/// advertises, so the right indexing is the one that puts a device's own frames inside its
/// own advertised slots:
///
/// ```text
///   sender             frames   aw%16 hits   (aw/pm)%16   slots
///   02:3b:e8:75:9c:03     596          34%         100%   [2, 8, 10]
///   2a:f3:94:4d:96:79     166          39%         100%   [0, 2, 8, 10]
///   be:35:be:c9:05:1f     276          34%         100%   [0, 2, 8, 10]
/// ```
///
/// 100% against a 25% chance level, five devices, 1397 frames, no exceptions.
///
/// Every captured device advertises `presence_mode: 4`. It is taken from the frame rather
/// than assumed, because it is a field and not a constant.
pub const DEFAULT_PRESENCE_MODE: u8 = 4;

/// One channel-sequence slot: `presence_mode` availability windows.
pub fn eaw_us(presence_mode: u8) -> u64 {
    u64::from(presence_mode.max(1)) * AW_US
}

/// A full sixteen-slot cycle: 1024 TU at presence mode 4, about 1.05 seconds.
pub fn cycle_us(presence_mode: u8) -> u64 {
    16 * eaw_us(presence_mode)
}

/// One observation: a frame arrived, and it said where in the schedule its sender was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    /// When we timestamped it, on our own monotonic clock.
    pub arrived_us: u64,
    /// `aw_counter` from the frame.
    pub counter: u16,
    /// `aw_remaining` from the frame, in TU.
    pub remaining_tu: u16,
    /// `presence_mode` from the same frame: how many AWs make a slot.
    pub presence_mode: u8,
}

impl Sighting {
    /// The moment the sender's current window ENDS, expressed on our clock.
    ///
    /// This is the whole trick in one line. Everything else here is averaging it.
    pub fn window_end_us(&self) -> u64 {
        self.arrived_us + u64::from(self.remaining_tu) * u64::from(TU_US)
    }

    /// Which slot of sixteen the sender was in.
    ///
    /// Divided by `presence_mode` first, because a slot is an extended AW. See
    /// [`DEFAULT_PRESENCE_MODE`] for how that was settled.
    pub fn slot(&self) -> usize {
        usize::from(self.counter / u16::from(self.presence_mode.max(1))) % 16
    }

    /// How far into the current SLOT the sender was, in microseconds.
    ///
    /// `aw_remaining` counts down within an availability window, and a slot holds
    /// `presence_mode` of them, so the position in the slot needs the window index too.
    pub fn into_slot_us(&self) -> u64 {
        let pm = u64::from(self.presence_mode.max(1));
        let aw_in_slot = u64::from(self.counter) % pm;
        let into_aw = AW_US.saturating_sub(u64::from(self.remaining_tu) * u64::from(TU_US));
        aw_in_slot * AW_US + into_aw
    }

    /// Where the cycle containing this frame began, on our clock.
    pub fn cycle_origin_us(&self) -> u64 {
        let slot_start = self.arrived_us.saturating_sub(self.into_slot_us());
        slot_start.saturating_sub(self.slot() as u64 * eaw_us(self.presence_mode))
    }
}

/// An estimate of a cluster's cycle phase, built from many sightings.
#[derive(Debug, Clone, Default)]
pub struct ClusterClock {
    /// `cycle_origin_us mod cycle` for each sighting, newest last.
    offsets: Vec<u64>,
    /// The presence mode the cluster advertises; sets the slot and cycle lengths.
    presence_mode: u8,
}

impl ClusterClock {
    pub fn new() -> ClusterClock {
        ClusterClock { offsets: Vec::new(), presence_mode: DEFAULT_PRESENCE_MODE }
    }

    /// One channel-sequence slot, microseconds.
    pub fn slot_us(&self) -> u64 {
        eaw_us(self.presence_mode)
    }

    /// A full sixteen-slot cycle, microseconds.
    pub fn cycle(&self) -> u64 {
        cycle_us(self.presence_mode)
    }

    /// How many sightings are backing the estimate.
    pub fn observations(&self) -> usize {
        self.offsets.len()
    }

    /// Fold in one sighting.
    ///
    /// Keeps a bounded history so a cluster that re-anchors is followed rather than
    /// averaged against its own past forever.
    pub fn observe(&mut self, s: Sighting) {
        const KEEP: usize = 64;
        // A changed presence mode changes the cycle length, so old offsets are measured
        // against a different ruler and cannot be averaged with new ones.
        if s.presence_mode.max(1) != self.presence_mode {
            self.presence_mode = s.presence_mode.max(1);
            self.offsets.clear();
        }
        let cycle = self.cycle();
        self.offsets.push(s.cycle_origin_us() % cycle);
        if self.offsets.len() > KEEP {
            let excess = self.offsets.len() - KEEP;
            self.offsets.drain(..excess);
        }
    }

    /// Forget every anchor.
    ///
    /// Called when the anchors stop being comparable — a different master, a different
    /// presence mode. An offset is measured against one cluster's timeline and means
    /// nothing against another's, so keeping them is worse than having none: the spread
    /// goes wide, `is_usable` says no, and the reason looks like jitter.
    pub fn reset(&mut self) {
        self.offsets.clear();
    }

    /// The estimated phase: where in our clock the cycle begins, modulo a cycle.
    ///
    /// **The newest sighting wins.** OWL's `awdl_sync_update_last` re-anchors on every
    /// frame from the master and averages nothing, and a run on hardware showed why: a
    /// median over 64 samples started at 0 µs of spread and degraded to 156 ms across
    /// seventy seconds — far wider than a 65 ms slot. Two clocks drift, so an estimate
    /// built from a minute of history is an estimate of where the cluster *was*.
    ///
    /// The history is kept, but for **health rather than for the estimate**: the spread of
    /// recent anchors says whether the last one can be trusted. That separation is the
    /// point — a median is robust to jitter and blind to drift, and this way jitter shows
    /// up in [`spread_us`](Self::spread_us) while drift cannot accumulate into the phase.
    pub fn phase_us(&self) -> Option<u64> {
        self.offsets.last().copied()
    }

    /// The phase a circular median of the whole history would give.
    ///
    /// Kept because it is the right estimate for a *static* offset and a useful contrast
    /// when diagnosing: if this and [`phase_us`](Self::phase_us) disagree by more than the
    /// spread, the two clocks are drifting rather than merely jittering.
    ///
    /// **Circular median, not mean.** The values live on a ring, so a cluster whose true
    /// phase sits near zero produces observations at both ends, and an arithmetic mean of
    /// those lands half a cycle away — maximally wrong, and plausible-looking.
    pub fn median_phase_us(&self) -> Option<u64> {
        if self.offsets.is_empty() {
            return None;
        }
        // Try each observation as the cut point for unwrapping the ring, and keep the
        // rotation with the least spread. With a few dozen points this is trivially cheap
        // and avoids the trigonometry.
        let cycle = self.cycle();
        let mut best: Option<(u64, u64)> = None; // (spread, phase)
        for cut in &self.offsets {
            let mut rotated: Vec<u64> =
                self.offsets.iter().map(|o| (o + cycle - cut) % cycle).collect();
            rotated.sort_unstable();
            let spread = rotated[rotated.len() - 1] - rotated[0];
            let median = rotated[rotated.len() / 2];
            let phase = (median + cut) % cycle;
            if best.is_none_or(|(s, _)| spread < s) {
                best = Some((spread, phase));
            }
        }
        best.map(|(_, p)| p)
    }

    /// How tightly the sightings agree, in microseconds.
    ///
    /// **Report this, do not hide it.** A USB adapter timestamps frames when they reach the
    /// kernel, not when they were on the air, so a spread approaching a whole window means
    /// the estimate is noise wearing a number's clothes.
    pub fn spread_us(&self) -> Option<u64> {
        if self.offsets.len() < 2 {
            return None;
        }
        // **Recent anchors only.** Drift makes a long history spread wide by construction,
        // so measuring all of it reports the clocks diverging as though it were noise. Eight
        // is a few seconds of frames from an active master.
        const RECENT: usize = 8;
        let recent: Vec<u64> =
            self.offsets.iter().rev().take(RECENT).copied().collect();
        let cycle = self.cycle();
        let mut best = u64::MAX;
        for cut in &recent {
            let mut rotated: Vec<u64> =
                recent.iter().map(|o| (o + cycle - cut) % cycle).collect();
            rotated.sort_unstable();
            best = best.min(rotated[rotated.len() - 1] - rotated[0]);
        }
        Some(best)
    }

    /// Whether the estimate is tight enough to act on.
    ///
    /// **The tolerance depends on where you aim, and an earlier version of this got it
    /// wrong.** It required a quarter window, which is the right bar for aiming at a slot
    /// *boundary*: miss by more and you land in the neighbour. But there is no reason to
    /// aim at a boundary. Aim at the window's **centre** and the margin is half a window
    /// either side — so an estimate is usable when half its spread fits inside that.
    ///
    /// It matters in practice rather than in principle. A real Apple cluster, measured
    /// through a USB adapter's host timestamps, gives a spread of about 5.1 ms against a
    /// 16.4 ms window: a third of a window, which the old bar rejected and which lands
    /// comfortably inside the right window when aimed at its middle.
    pub fn is_usable(&self) -> bool {
        let half_slot = self.slot_us() / 2;
        self.observations() >= 4 && self.spread_us().is_some_and(|s| s / 2 < half_slot)
    }

    /// Microseconds from `now_us` until the MIDDLE of the cluster's slot `slot`.
    ///
    /// Prefer this to [`us_until_slot`](Self::us_until_slot) for anything that actually
    /// transmits. The boundary is the worst place to aim: it is where half the estimate's
    /// error puts you in the wrong window. The middle is the furthest point from both.
    pub fn us_until_slot_centre(&self, now_us: u64, slot: usize) -> Option<u64> {
        let (phase, cycle, sl) = (self.phase_us()?, self.cycle(), self.slot_us());
        let target = (phase + (slot as u64 % 16) * sl + sl / 2) % cycle;
        Some((target + cycle - (now_us % cycle)) % cycle)
    }

    /// Microseconds from `now_us` until the cluster's slot `slot` next begins.
    pub fn us_until_slot(&self, now_us: u64, slot: usize) -> Option<u64> {
        let (phase, cycle, sl) = (self.phase_us()?, self.cycle(), self.slot_us());
        let target = (phase + (slot as u64 % 16) * sl) % cycle;
        Some((target + cycle - (now_us % cycle)) % cycle)
    }

    /// Which cluster slot `now_us` falls in, if the phase is known.
    pub fn slot_at(&self, now_us: u64) -> Option<usize> {
        let (phase, cycle, sl) = (self.phase_us()?, self.cycle(), self.slot_us());
        Some((((now_us + cycle - phase) % cycle) / sl) as usize)
    }
}

/// What we have learned about a cluster by listening to it.
#[derive(Debug, Clone, Default)]
pub struct Cluster {
    /// The address every node names as master, if they agree.
    pub master: Option<[u8; 6]>,
    /// The master's advertised metric — what we would have to beat.
    pub master_metric: Option<u32>,
    /// The slots the master says it occupies.
    pub master_slots: Vec<usize>,
    /// Our own address, so a peer naming US can be told from a cluster to follow.
    pub self_addr: Option<[u8; 6]>,
    /// Peers that have named us master, and how many frames each spent saying so.
    ///
    /// **This is an outcome, not a cluster.** Before it existed, a peer adopting us set
    /// `master` to our own address — after which nothing could ever anchor the clock,
    /// because the anchoring test is `master == src` and our own frames are filtered out.
    /// `adopted` then went false and the run looked starved. Being adopted turned itself
    /// into a broken measurement, which is close to the worst failure a measurement can
    /// have.
    pub adopters: std::collections::BTreeMap<[u8; 6], u32>,
    /// How many times we have changed which cluster we follow.
    ///
    /// Worth reporting rather than hiding. A run in a busy room that changes master
    /// repeatedly is not synchronising to anything, and the symptom without this counter is
    /// a spread figure that looks like jitter and is actually two clusters.
    pub master_changes: u32,
    pub clock: ClusterClock,
}

impl Cluster {
    pub fn new() -> Cluster {
        Cluster::default()
    }

    /// A tracker that knows its own address, and so can tell being adopted from finding a
    /// cluster. Prefer this to [`new`](Self::new) anywhere real frames are involved.
    pub fn for_us(addr: [u8; 6]) -> Cluster {
        Cluster { self_addr: Some(addr), ..Cluster::default() }
    }

    /// How many frames peers have spent naming us master, across all of them.
    pub fn adoption_frames(&self) -> u32 {
        self.adopters.values().sum()
    }

    /// Fold in one received frame.
    ///
    /// `sync` and `election` come from the same frame; passing parts of different frames
    /// would attribute one node's schedule to another's clock.
    pub fn observe(
        &mut self,
        arrived_us: u64,
        src: [u8; 6],
        sync: &SyncParams,
        election: Option<&ElectionParamsV2>,
    ) {
        if let Some(e) = election {
            // A PEER NAMING US IS NOT A CLUSTER TO FOLLOW. It is the thing we are trying
            // to cause. Recorded and stepped over: following it would set `master` to our
            // own address, and since only the master's own frames anchor the clock and our
            // own frames are filtered, the estimate would be frozen at zero observations
            // for the rest of the run.
            if self.self_addr == Some(e.master) {
                *self.adopters.entry(src).or_insert(0) += 1;
                return;
            }

            // Follow the cluster's own opinion of who is master rather than picking the
            // loudest sender: a node at distance 2 still names the root correctly.
            //
            // BUT DO NOT TAKE EVERY FRAME'S WORD FOR IT. A room with two clusters names
            // two different masters, and assigning `self.master` unconditionally makes it
            // flap on alternate frames -- which then lets BOTH masters' frames anchor the
            // clock, since the anchoring test is `self.master == Some(src)`. Offsets from
            // two unrelated timelines pool together and the spread goes to hundreds of
            // milliseconds against a 65 ms slot. Measured on hardware at 188 ms and 368 ms
            // in consecutive runs, each naming a different master. Finding 55.
            //
            // The rule is AWDL's own: follow the better metric. A weaker cluster is
            // ignored rather than averaged in, and an EQUAL metric does not displace the
            // incumbent -- otherwise two clusters that happen to match would flap forever.
            let claimed = if e.master == src { e.self_metric } else { e.master_metric };
            let switch = match (self.master, self.master_metric) {
                (None, _) => true,
                (Some(m), _) if m == e.master => true,
                (Some(_), Some(have)) => claimed > have,
                (Some(_), None) => true,
            };
            if switch {
                if self.master != Some(e.master) {
                    // A different cluster: every anchor we hold was measured against the
                    // old one's timeline and is now meaningless.
                    self.clock.reset();
                    self.master_slots.clear();
                    self.master_changes += 1;
                }
                self.master = Some(e.master);
                if claimed != 0 {
                    self.master_metric = Some(claimed);
                }
            }
        }

        // Only the master's own frames anchor the clock. A follower's aw_counter is its own
        // and may not have converged, so averaging it in would blur the very thing we want.
        if self.master == Some(src) {
            if let Some(seq) = &sync.channel_sequence {
                self.master_slots = seq
                    .channels
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| **c != 0)
                    .map(|(i, _)| i)
                    .collect();
            }
            self.clock.observe(Sighting {
                arrived_us,
                counter: sync.aw_counter,
                remaining_tu: sync.aw_remaining,
                presence_mode: sync.presence_mode,
            });
        }
    }

    /// When the next window the MASTER occupies begins, on our clock.
    ///
    /// This is the point of the whole module: transmit here and we are on the air at a
    /// moment the cluster is demonstrably awake, rather than at a phase decided by when our
    /// process happened to start.
    pub fn us_until_master_window(&self, now_us: u64) -> Option<u64> {
        if !self.clock.is_usable() || self.master_slots.is_empty() {
            return None;
        }
        // ALREADY INSIDE ONE? Then the answer is now, not the next centre.
        //
        // Aiming at the centre is right when we are outside a window and wrong the moment
        // we are inside one: `us_until_slot_centre` returns the time to the NEXT centre, so
        // overshooting by a microsecond costs a full cycle. Measured on hardware, that is
        // what it cost — a 30-second run against a cluster we were correctly synchronised
        // to (spread 8.6 ms, adopted) transmitted FOUR frames, because every window was
        // missed by a hair and then waited 1.049 s for the next.
        //
        // A window is 65 ms wide and the whole point of knowing the phase is to transmit
        // inside it. The caller is responsible for not sending twice in one visit; that is
        // a smaller problem than never sending at all.
        if let Some(now_slot) = self.clock.slot_at(now_us) {
            if self.master_slots.contains(&now_slot) {
                return Some(0);
            }
        }
        // Outside: aim at the centre, not the boundary — see
        // ClusterClock::us_until_slot_centre.
        self.master_slots
            .iter()
            .filter_map(|s| self.clock.us_until_slot_centre(now_us, *s))
            .min()
    }
}
