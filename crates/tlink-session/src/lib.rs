#![forbid(unsafe_code)] // security review: keep these pure-logic crates unsafe-free
//! The held AWDL session: one loop that listens, keeps the cluster clock, transmits in the
//! windows it advertises, and carries the data path — over any [`tlink_hal::Radio`].
//!
//! This is the logic that used to live inside the CLI's `beacon` subcommand. It is a library
//! so two callers can share it: the CLI (a fixed-duration run that prints a summary) and the
//! `libmosey`-ABI shim (an open-ended run driven by a stop flag, hosting the real daemon's
//! transport). Both build a radio, bring it up, and hand it here.
//!
//! Progress goes through the `log` facade rather than `eprintln!`, so the CLI can route it to
//! stderr and the shim to Android's `liblog`. The loop never calls `std::process::exit`; a
//! setup failure is an `Err`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tlink::beacon::{Beacon, FollowAdvert, Garbage};
use tlink::follow::Cluster;
use tlink_hal::{Error, Radio, Result, TxParams};

/// How the session should behave. The knobs that were CLI flags.
pub struct Config {
    pub channel: u8,
    pub country: [u8; 2],
    /// One MIF (full frame) per this many PSFs. 0 = every frame a MIF.
    pub psf_per_mif: u32,
    /// Announce [`tlink::beacon::METRIC_COMPETE`].
    pub compete: bool,
    /// Override the metric outright.
    pub metric: Option<u32>,
    /// Announce the decline metric for this many seconds, then step to the real one.
    pub metric_floor: Option<u64>,
    /// PSFs per advertised window (experimental control; 1 in normal use).
    pub per_window: u32,
    pub windows: Option<usize>,
    /// Aim transmits at the cluster's windows once its clock is usable.
    pub follow: bool,
    /// Follow the master's channel sequence: retune the radio to each master window's channel
    /// so our frames land on the channel the peer attends, not just at the right time. Needs
    /// `follow`; without it a multi-channel cluster (e.g. [6, 149]) is only intermittently
    /// reachable — see finding 99. The radio backend must support live `set_channel`.
    pub follow_channels: bool,
    /// Single-channel backend that cannot hop (wonder — findings 100/101): transmit only in the
    /// master's windows that are on our channel, and lift the one-frame-per-window throttle so we
    /// send several PSFs into each such window. A hop-less radio can still be peered by Apple, but
    /// only if its sync frames arrive while the peer is on our channel, and often enough to hold a
    /// peer-table entry.
    pub channel_lock: bool,
    /// Transmit the instant we receive a frame from the master, instead of only on our
    /// software-computed window schedule. When a master frame arrives we are provably inside
    /// the master's availability window on its channel, so a frame sent right then lands where
    /// the whole cluster is awake and listening — the window alignment a host-timestamp clock
    /// cannot guarantee, and (per the libmosey trace, findings 100-103) how a software stack on
    /// a hop-less radio actually gets its frames into the window.
    pub reactive: bool,
    /// Minimum microseconds between BEACON (PSF/MIF) transmissions, shared across the reactive
    /// and scheduled paths. `channel_lock` lifts the one-frame-per-window throttle to burst PSFs
    /// on a hop-less radio, and `reactive` fires on hearing the master; with no shared floor the
    /// two together flooded the social channel at ~107 frames/s — ~12x any Apple peer (~9/s) —
    /// starving the peer's own transmit slots (finding 126: tap->/Ask ~5s, SYNs queued for a
    /// window). This caps the combined beacon rate WITHOUT throttling the in-window data drain,
    /// so bulk throughput is unaffected. 0 = no cap (the old flooding behaviour).
    pub beacon_min_gap_us: u64,
    /// Use this AWDL address instead of the radio's hardware MAC. Apple devices rotate a fresh
    /// locally-administered MAC every AWDL session (privacy), and a peer that reuses one fixed
    /// address across many failed discovery attempts can be negatively cached. `None` keeps the
    /// radio's own MAC.
    pub override_mac: Option<[u8; 6]>,
    pub tenure: Option<u32>,
    pub legacy_timing: bool,
    pub version: Option<(u8, u8)>,
    pub garbage: Option<Garbage>,
    /// Name of a TUN to bring up and carry IP over (e.g. `tlink0`). None = control plane only.
    pub datapath: Option<String>,
    /// Originate an 802.11 Block Ack agreement with the master and log the peer's ADDBA
    /// Response / BlockAck frames. The de-risking probe for real outbound ARQ (finding 105):
    /// injection has no hardware ARQ, so to make bulk send reliable we must run Block Ack in
    /// software, which only works if the peer honours an ADDBA *we* originate. It does not
    /// (finding 106) — kept only for reading the peer's BA traffic.
    pub blockack: bool,
    /// Transmit each outbound **data** frame this many times (repetition FEC). Our inject path
    /// has no link-layer ARQ and iOS will not Block-Ack us (finding 106), so a lost data frame
    /// is only recovered by TCP — whose retransmits hit the same ~10% loss and stall. Sending
    /// each frame N× with the 802.11 Retry bit set and the SAME sequence number lets the peer's
    /// standard duplicate-detection keep one and drop the rest, turning ~10% loss into ~10%^N.
    /// 1 = off (one transmission). Control frames/beacons are never repeated.
    pub data_repeat: u32,
    /// Data frames drained per window visit. See `DRAIN_PER_WINDOW` for why 24 is the default.
    ///
    /// Settable because it is the one knob that decides how long we hold the air in one go, and
    /// that matters when the PEER is another copy of us. A peer running this code answers inbound
    /// data on the immediate-ACK path — at once, no throttle, no per-window cap — while a radio in
    /// monitor injection is deaf for as long as it transmits. So a long burst from us arrives while
    /// the peer is trying to acknowledge the front of it, and neither side hears the other. Against
    /// an iPhone none of this applies: it defers in hardware and acknowledges on the firmware's
    /// timing. A shorter burst should therefore be FASTER device-to-device and slower to Apple,
    /// which is the opposite of what a bandwidth knob usually does, and is why it is measurable
    /// rather than assumed.
    pub drain_per_window: usize,
    /// Stop after this long. None = run until the stop flag is set (the shim's mode).
    pub duration: Option<Duration>,
}

impl Config {
    /// A minimal control-plane config on one channel.
    pub fn new(channel: u8, country: [u8; 2]) -> Config {
        Config {
            channel,
            country,
            psf_per_mif: 2,
            compete: false,
            metric: None,
            metric_floor: None,
            per_window: 1,
            windows: None,
            follow: false,
            follow_channels: false,
            channel_lock: false,
            reactive: false,
            // ~16/s. Measured reference: libmosey on the same hop-less wonder radio peers iPhones
            // at ~7.5/s (finding 126), so this is 2x that for our looser software-timing drift.
            beacon_min_gap_us: 60_000,
            override_mac: None,
            tenure: None,
            legacy_timing: false,
            version: None,
            garbage: None,
            datapath: None,
            blockack: false,
            data_repeat: 1,
            drain_per_window: DRAIN_PER_WINDOW,
            duration: None,
        }
    }
}

/// What the session did, for the caller to report.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub sent_mif: u64,
    pub sent_psf: u64,
    pub failed: u64,
    pub tx_latency_est: u64,
    pub tx_latency_seen: u64,
    pub adopters: usize,
    pub adoption_frames: u32,
    pub adopter_list: Vec<([u8; 6], u32)>,
    pub datapath: bool,
    pub dp_sent: u64,
    pub dp_recvd: u64,
    pub dp_noroute: u64,
    pub dp_dropped: u64,
    pub outbound_len: usize,
    pub rx_mgmt: u64,
    pub rx_ctrl: u64,
    pub rx_data: u64,
    pub anchors: usize,
    pub master: Option<[u8; 6]>,
    pub phase_us: Option<u64>,
    pub spread_us: Option<u64>,
    pub master_changes: u32,
    pub adopted: bool,
    /// How many times we retuned the radio to follow the master's channel sequence.
    pub hops: u64,
    /// How many retune attempts the radio rejected.
    pub hop_fail: u64,
    pub first_error: Option<String>,
}

/// Bounded outbound queue. Sized to hold a bulk TCP burst in flight: a 419 KB AirDrop
/// upload is ~290 full-MSS segments, and the queue has to absorb a window's worth of them
/// between drains without discarding any. When it is full we stop reading the tun (see
/// `enqueue_from_tun`) rather than dropping — a dropped TCP segment on our inject path has
/// no link-layer retransmit, so a drop becomes a stall, not a hiccup. Backpressure at the
/// tun instead lets the kernel's own TCP flow control pace the sender to our drain rate.
const OUTBOUND_MAX: usize = 512;
/// Data frames drained per window visit. Was 4, which capped bulk send at ~250 frames/s
/// (~360 KB/s ceiling, and far less once drops forced TCP to back off) — enough for a
/// one-frame `/Discover` or `/Ask` but not a `/Upload`. At HT MCS 11 (~52 Mb/s) a 1500-byte
/// frame is ~0.25 ms on air, so 24 frames is ~6 ms — comfortably inside a 16 TU (~16.4 ms)
/// availability window, without overrunning into the next slot.
const DRAIN_PER_WINDOW: usize = 24;
/// How many times to transmit each ACK on the immediate-ACK path. Our inject path has no
/// link-layer ARQ, and a lost ACK is a full TCP RTO stall (seconds), not a hiccup — while an ACK
/// is ~40 bytes. Sending it 3× (same seq, Retry bit; the peer de-duplicates) makes a ~p loss ~p³
/// for negligible airtime. Finding 110.
const ACK_REPEAT: u32 = 3;
/// A drain of at most this many queued frames is a "small burst" — a control/handshake exchange
/// (the `/Discover`, `/Ask`, TLS and 200-response frames of the startup), not bulk data. Small
/// bursts are transmitted redundantly (`ACK_REPEAT`) because a single lost control frame is a
/// multi-second TCP RTO stall at connection setup (measured: 8 s `/Discover`→`/Ask`, 12 s
/// accept→`/Upload`, finding 113). A large burst is bulk data: repeating it only adds contention.
const SMALL_BURST_MAX: usize = 6;

/// Frames longer than this are payload, never control, and are NOT repeated.
///
/// The small-burst rule above classified by QUEUE LENGTH alone, and during bulk that misfires:
/// we drain faster than TCP fills, so the queue is usually short at drain time, and MSS-sized
/// payload frames were being sent three times as if they were handshake frames. Measured on air
/// 2026-09-25 with data_repeat=1: of 20,969 bulk data frames from us, 16,565 carried the Retry
/// bit — 79% of the transfer was our own duplicates. Three times the airtime the peer's ACKs
/// must share, and it is why data_repeat 1 vs 3 changed nothing: most frames were already
/// tripled by this path. A TCP ACK, SYN, TLS record or HTTP head is a few hundred bytes; a
/// payload frame is ~1450. Size separates them cleanly.
const CONTROL_FRAME_MAX: usize = 400;

/// Seconds the running session has been BLIND: a master adopted and the cluster clock not
/// usable, so every data frame goes out in slots nobody listens in. Zero when synced, when
/// alone, or when no session runs.
///
/// Why a process-wide atomic: the shim hands `tarishd` an opaque handle and the daemon only
/// speaks the five-symbol libmosey ABI, so the one channel back is another optional symbol,
/// `mosey_health`, which reads this. Measured 2026-09-25: a re-election adopted a master we
/// never heard (`anchors 0, usable false`) and discovery stayed dead for five minutes until a
/// manual daemon restart brought a fresh session up in two seconds. The proper fix is in the
/// follow logic (task #48); this is what lets the daemon do that restart itself.
pub static BLIND_SECS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Run the session on `radio` (already brought up) until `stop` is set or `cfg.duration`
/// elapses. Returns what it did.
pub fn run(radio: &mut dyn Radio, cfg: &Config, stop: &AtomicBool) -> Result<Stats> {
    let addr = match cfg.override_mac {
        Some(m) => {
            log::info!("using override AWDL MAC {}", tlink::dot11::Mac(m));
            m
        }
        None => radio.mac_address()?,
    };
    let mut b = Beacon::new(addr, cfg.channel, core::str::from_utf8(&cfg.country).unwrap_or("QA"));
    // A radio that cannot hop must advertise only the channel it is on (finding 127): the
    // Apple-shaped [6, 149] sequence sends peers to ch6 slots we are never in, so their connection
    // attempts miss until one lands on our real channel — the ~5s tap->/Ask delay. libmosey on this
    // same hop-less radio advertises a single channel and iOS connects in ~1.5s.
    b.single_channel = cfg.channel_lock;

    if let Some((major, minor)) = cfg.version {
        b.version = tlink::state::Version { major, minor, device_class: 2 };
    }
    log::info!("announcing AWDL v{}.{}", b.version.major, b.version.minor);

    let mut cluster = Cluster::for_us(addr);
    let mut adopted = false;
    // Sync health, which was previously invisible between adoption and loss.
    //
    // The ADOPTED/DROPPED line fires only when is_usable() FLIPS, so a master CHANGE while the
    // clock stays nominally usable said nothing at all — and the master is what defines the
    // availability windows that data frames (and therefore mDNS, and therefore discovery) ride
    // in. A whole evening was spent guessing at peers that came and went with no way to see
    // whether the cluster underneath had changed master or degraded. These two make it legible.
    let mut last_master: Option<[u8; 6]> = None;
    let mut last_health = Instant::now();
    // The master's advertised channel sequence, logged once per change: which of its 16 slots
    // it spends on 6 / 44 / 149. Our transmit is locked to one channel, so this is the schedule
    // that decides whether a frame of ours can be heard at all.
    let mut last_master_seq: Option<Vec<u8>> = None;
    let mut peer_seq: std::collections::HashMap<[u8; 6], Vec<u8>> = std::collections::HashMap::new();
    // Every transmitted DATA frame, classified against the master's advertised schedule at the
    // instant it left: did it go out in one of the master's awake slots, one of its asleep
    // slots, or with no usable clock at all. This is the question the Pi cannot answer (its
    // fold needs a slot-0 reference it does not have) and the session can, exactly: it owns the
    // clock model and the master's slot list. A thin master schedule (2-5 awake of 16) is where
    // a slot-numbering error would show as loss and as "hear its beacons, never its data".
    let (mut tx_awake, mut tx_asleep, mut tx_noclock) = (0u64, 0u64, 0u64);
    let mut rxs = RxStages::default();
    // When the clock last became unusable with a master adopted; see BLIND_SECS.
    let mut blind_since: Option<Instant> = None;
    BLIND_SECS.store(0, Ordering::Relaxed);

    // Data plane: the TUN shares this loop and this radio (two processes cannot both inject
    // on one phy). Outbound IP is queued and drained in-window, because an AWDL peer listens
    // only during its availability windows.
    let tundev = open_datapath(cfg.datapath.as_deref(), addr)?;
    let mut outbound: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut tbuf = vec![0u8; 4096];
    let (mut dp_sent, mut dp_recvd, mut dp_noroute, mut dp_dropped) = (0u64, 0u64, 0u64, 0u64);
    // Frames the kernel handed us to send, counted where they leave the TAP. Without it there
    // is no way to tell a starved drain from an idle one.
    let mut dp_queued = 0u64;
    let (mut rx_mgmt, mut rx_ctrl, mut rx_data) = (0u64, 0u64, 0u64);
    let mut awdl_data_seq: u16 = 0;
    let mut d11_data_seq: u16 = 0;

    if cfg.compete {
        b.metric = tlink::beacon::METRIC_COMPETE;
    }
    if let Some(m) = cfg.metric {
        b.metric = m;
    }
    // --metric-floor: announce the decline metric first, then step. This is what Apple does
    // (finding 77) — the floor is a claim about being a credible timing anchor.
    let target_metric = b.metric;
    let floor_until = cfg.metric_floor.map(|s| Instant::now() + Duration::from_secs(s));
    if cfg.metric_floor.is_some() {
        b.metric = tlink::beacon::METRIC_DECLINE;
    }
    if let Some(t) = cfg.tenure {
        b.tenure_base = t;
    }
    if let Some(w) = cfg.windows {
        b.windows = Some(w);
    }
    // A single-channel backend that never leaves its channel must advertise DENSE presence —
    // all 16 slots on that channel — so a browsing peer knows it is always reachable there.
    // Stock libmosey does exactly this (16x ch6); our default apple_shaped schedule claims only
    // ~4 slots, which tells the peer we are asleep 12/16 of the time and is why iOS would not
    // peer us. windows=Some(16) makes schedule() emit all 16 slots on our channel.
    if cfg.channel_lock {
        b.windows = Some(16);
        b.stock_dp_shape = true;
    }
    if let Some(g) = cfg.garbage {
        b.garbage = g;
    }
    if cfg.legacy_timing {
        b.legacy_timing = true;
    }

    log::info!(
        "session up: ch{} metric {} {}{}",
        cfg.channel,
        b.metric,
        if cfg.follow { "following" } else { "self-timed" },
        if tundev.is_some() { " +datapath" } else { "" },
    );

    // One monotonic epoch; every timing field is derived from it, which is what makes them
    // self-consistent.
    let epoch = Instant::now();
    let epoch_realtime_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let deadline = cfg.duration.map(|d| epoch + d);

    let (mut sent_mif, mut sent_psf, mut failed) = (0u64, 0u64, 0u64);
    let mut last_tx_us = 0u64;
    let mut n = 0u32;
    let mut first_error: Option<String> = None;
    let mut stepped = false;
    // Injection-latency estimate, seeded at a real device's median and refined per tx().
    let mut tx_latency_est: u64 = 100;
    let mut tx_latency_seen: u64 = 0;
    // The channel the radio is currently tuned to. We only retune on a change, so
    // channel-following costs one ~0.6 ms set_channel per slot transition (finding 99), not
    // one per loop pass.
    let mut current_channel = cfg.channel;
    let mut hops = 0u64;
    let mut hop_fail = 0u64;
    let mut last_reactive_us = 0u64;
    let mut reactive_tx = 0u64;
    // TSF anchoring for the cluster clock. wonder0 delivers a real radiotap TSFT (the firmware's
    // hardware receive time) on every frame; anchoring the cluster phase on it instead of the
    // host arrival time removes the socket/processing jitter that made the spread swing 0-13 ms
    // and the estimate "drop" (finding 108). We keep the newest (tsf, host) pair and read "now
    // in TSF" from it for the master-clock queries; deltas are then base-invariant to sleep on.
    let mut tsf_anchor: Option<u64> = None;
    let mut host_at_anchor_us: u64 = 0;
    // Block Ack probe (cfg.blockack): originate an ADDBA to the master and watch for the peer's
    // ADDBA Response / BlockAck. State for the send throttle and what we have seen back.
    let mut ba_last_addba_us = 0u64;
    let mut ba_dialog: u8 = 0;
    let mut ba_resp_seen = 0u64;
    let mut ba_ack_seen = 0u64;
    let mut ba_mgmt_seq: u16 = 0;
    // Diagnostic: how many beacons went out on each channel, and the slots we transmitted in.
    let mut tx_by_channel: std::collections::BTreeMap<u8, u64> = std::collections::BTreeMap::new();
    let mut tx_by_slot: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();

    while !stop.load(Ordering::Relaxed) {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        // Step off the metric floor once, at the boundary.
        if let Some(t) = floor_until {
            if !stepped && Instant::now() >= t {
                b.metric = target_metric;
                stepped = true;
                log::info!("metric floor lifted: now announcing {target_metric}");
            }
        }

        // LISTEN. A frame carries aw_counter and aw_remaining, which place a slot boundary on
        // our clock. Drain what is waiting, bounded by the slack before the next window.
        {
            let slack_us = {
                let now_host = epoch.elapsed().as_micros() as u64;
                let now_tsf = tsf_anchor
                    .map(|t| t + now_host.saturating_sub(host_at_anchor_us))
                    .unwrap_or(now_host);
                match cluster.us_until_master_window(now_tsf) {
                    Some(w) if adopted => w,
                    _ => b.us_until_next_advertised_window(now_host),
                }
            };
            let budget_ms = if slack_us < 4_000 { 0 } else { 2 };
            // Finding 121: at ch149 libmosey pushes ~2150 data-fps, we sustained ~563. We only
            // RX during window-aligned visits (~17/s), so the per-visit cap directly sets the
            // frame rate: 32 x ~17 ~= 563. The `else break` already stops the instant the socket
            // is empty, so a higher cap is "drain everything that queued this visit" — only a
            // sustained burst reaches it. Raise it (4->32 near a window, 32->128 otherwise) so we
            // can absorb and immediately-ACK a full window's burst instead of leaving frames in the
            // kernel buffer, which paces the peer down. Experiment for the 4x RX/ACK target.
            let max_drain = if slack_us < 4_000 { 32 } else { 128 };

            let mut heard_master = false;
            let dp_recvd_before = dp_recvd;
            let mut drained = 0;
            while drained < max_drain {
                if let Ok(Some(rx)) = radio.rx(if drained == 0 { budget_ms } else { 0 }) {
                    drained += 1;
                    // The kernel's arrival time, not ours: a socket backlog otherwise gets
                    // added to every frame behind it.
                    let host_now_us = rx
                        .host_us
                        .map(|t| t.saturating_sub(epoch_realtime_us))
                        .unwrap_or_else(|| epoch.elapsed().as_micros() as u64);
                    // Anchor the cluster clock on the hardware TSF when present (wonder0 supplies
                    // it), falling back to the host arrival time only if it is not. `now_us` is
                    // what we hand the cluster: the frame's own on-air time, so the phase carries
                    // no processing jitter. We also refresh the TSF<->host mapping used to read
                    // "now in TSF" for transmit scheduling below.
                    let now_us = if let Some(tsf) = rx.tsf {
                        tsf_anchor = Some(tsf);
                        host_at_anchor_us = epoch.elapsed().as_micros() as u64;
                        tsf
                    } else {
                        host_now_us
                    };
                    match frame_type(&rx.bytes) {
                        Some(2) => rx_data += 1,
                        Some(1) => rx_ctrl += 1,
                        Some(_) => rx_mgmt += 1,
                        None => {}
                    }
                    if cfg.blockack {
                        if let Some(resp) = tlink::blockack::parse_addba_response(&rx.bytes, addr) {
                            ba_resp_seen += 1;
                            log::info!(
                                "BLOCKACK PROBE: peer ADDBA RESPONSE — accepted={} tid={} buffer_size={} immediate={} (dialog {:#04x}); the iPhone honours an ARQ session we originate",
                                resp.accepted(), resp.tid, resp.buffer_size, resp.immediate, resp.dialog_token
                            );
                        }
                        if let Some(ba) = tlink::blockack::parse_block_ack(&rx.bytes, addr) {
                            ba_ack_seen += 1;
                            log::info!(
                                "BLOCKACK PROBE: peer BlockAck — ssn={} tid={} compressed={} bitmap={:#018x}",
                                ba.ssn, ba.tid, ba.compressed, ba.bitmap
                            );
                        }
                    }
                    if tundev.is_some() {
                        deliver_data_frame(&rx.bytes, addr, tundev.as_ref(), &mut dp_recvd, &mut rxs);
                    }
                    if let Some((src, sync, elect, chanseq, phy_tx_time)) = parse_awdl(&rx.bytes) {
                        // Never synchronise to our own transmissions handed back by the monitor.
                        if src != addr {
                            // EVERY peer's advertised schedule, once per change — not only the
                            // master's. Discovery of one iPhone works only while a second Apple
                            // device is present; the question is whether the first one's own
                            // awake-slot count changes with company (its schedule) or with a
                            // sender's BLE (its duty cycle), and that needs per-peer visibility.
                            if let Some(cs) = chanseq.as_ref() {
                                let e = peer_seq.entry(src).or_insert_with(Vec::new);
                                if *e != cs.channels {
                                    let n = |c: u8| cs.channels.iter().filter(|&&x| x == c).count();
                                    log::info!(
                                        "PEER {} SCHEDULE {:?}: awake on 149={}, 6={}, 44={}, asleep={}",
                                        tlink::dot11::Mac(src), cs.channels, n(149), n(6), n(44), n(0)
                                    );
                                    *e = cs.channels.clone();
                                }
                            }
                            cluster.observe_at(now_us, src, &sync, elect.as_ref(), phy_tx_time);
                            // Prefer the OpClass channel map (tag 18) for the master's schedule:
                            // the Legacy one in Sync Params encodes a 40 MHz centre we cannot
                            // tune to (finding 99). Only the master's own sequence counts.
                            if cluster.master == Some(src) {
                                if let Some(cs) = chanseq {
                                    if last_master_seq.as_ref() != Some(&cs.channels) {
                                        let n = |c: u8| cs.channels.iter().filter(|&&x| x == c).count();
                                        log::info!(
                                            "MASTER CHANNEL SEQUENCE {:?}: slots on 149={}, 6={}, 44={}, other={}",
                                            cs.channels, n(149), n(6), n(44),
                                            cs.channels.iter().filter(|&&x| x != 149 && x != 6 && x != 44).count()
                                        );
                                        last_master_seq = Some(cs.channels.clone());
                                    }
                                    cluster.set_master_channels(&cs);
                                }
                                heard_master = true;
                                if cfg.blockack {
                                    // Diagnostic: compare the coarse counter/remaining phase with
                                    // one derived from the master's own TSF (phy_tx_time). cycle
                                    // is 1048576 us at pm 4. Test phy as microseconds and as TU,
                                    // to see which gives a stable rx.tsf - (phy % cycle).
                                    let cycle = tlink::follow::cycle_us(sync.presence_mode.max(1));
                                    let origin_us = rx.tsf.map(|t| t.wrapping_sub((phy_tx_time as u64) % cycle) % cycle);
                                    let origin_tu = rx.tsf.map(|t| t.wrapping_sub(((phy_tx_time as u64) * 1024) % cycle) % cycle);
                                    log::info!(
                                        "PHASE: tsf={:?} phy={} slot={} counter_phase={:?} spread={:?} | phy_origin_us={:?} phy_origin_tu={:?}",
                                        rx.tsf, phy_tx_time,
                                        (sync.aw_counter / u16::from(sync.presence_mode.max(1))) % 16,
                                        cluster.clock.phase_us(), cluster.clock.spread_us(),
                                        origin_us, origin_tu
                                    );
                                }
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            // IMMEDIATE ACK. If a peer just sent us data, it is awake and listening RIGHT NOW —
            // receiving from it is proof of that, better than any scheduled window. So pull the
            // TCP ACKs the kernel just generated and inject them at once, instead of parking them
            // in the outbound queue until the next windowed drain. Parking them delayed every ACK
            // by ~a window (16-65 ms), inflating the peer's RTT and stalling its send: measured at
            // ~22 inbound frames/s with 111 half-second stalls, against stock's ~220 fps and none
            // (finding 109). This is the reactive-beacon trick applied to the data path: we just
            // heard the peer, so transmit to it now — no throttle, no per-window cap.
            if dp_recvd > dp_recvd_before {
                if let Some(t) = tundev.as_ref() {
                    // Drain generously: a burst of inbound data yields a burst of ACKs, and they
                    // are small. Loop until the tun has nothing more queued this instant.
                    for _ in 0..64 {
                        let before = outbound.len();
                        enqueue_from_tun(
                            t, addr, &mut tbuf, &mut outbound, OUTBOUND_MAX,
                            &mut d11_data_seq, &mut awdl_data_seq, &mut dp_noroute, &mut dp_dropped,
                            &mut dp_queued,
                        );
                        let read = outbound.len().saturating_sub(before);
                        // A small burst here is a control/handshake response (e.g. our /Ask 200)
                        // the kernel generated right after we delivered the request — repeat it so
                        // a lost setup frame does not become a multi-second RTO stall (finding 113).
                        // A large burst is bulk-data ACKs: send once, as repeating them only adds
                        // contention with no measurable gain (finding 110).
                        let small = outbound.len() <= SMALL_BURST_MAX;
                        let reps: u32 = if small { ACK_REPEAT } else { 1 };
                        // Bulk goes at the interface's configured rate; a small control burst
                        // keeps the pinned legacy rate, which is what stock uses for the same
                        // frames. See TxParams::legacy_ofdm.
                        let tp = if small { TxParams::default() } else { TxParams::bulk() };
                        while let Some(f) = outbound.pop_front() {
                            {
                                let now_host = epoch.elapsed().as_micros() as u64;
                                let now_tsf = tsf_anchor.map(|t| t + now_host.saturating_sub(host_at_anchor_us)).unwrap_or(now_host);
                                match (cluster.clock.is_usable(), cluster.clock.slot_at(now_tsf)) {
                                    (true, Some(sl)) if cluster.master_slots.contains(&sl) => tx_awake += 1,
                                    (true, Some(_)) => tx_asleep += 1,
                                    _ => tx_noclock += 1,
                                }
                            }
                            match radio.tx(&f, tp) {
                                Ok(()) => dp_sent += 1,
                                Err(e) => { failed += 1; if first_error.is_none() { first_error = Some(format!("{e:?}")); } }
                            }
                            if reps > 1 && f.len() >= 2 && f.len() <= CONTROL_FRAME_MAX {
                                let mut dup = f.clone();
                                dup[1] |= 0x08;
                                for _ in 1..reps {
                                    if radio.tx(&dup, tp).is_ok() { dp_sent += 1; }
                                }
                            }
                        }
                        if read == 0 {
                            break; // the tun had nothing more to send this instant
                        }
                    }
                }
            }

            let usable = cluster.clock.is_usable();
            // Publish "blind": a master adopted and no usable clock. tarishd reads this through
            // the shim's `mosey_health` and restarts the session when it has lasted a minute
            // (task #48). Alone in the cluster, unusable is normal and is not blind.
            if cfg.follow && cluster.master.is_some() && !usable {
                let since = *blind_since.get_or_insert_with(Instant::now);
                BLIND_SECS.store(since.elapsed().as_secs().min(u32::MAX as u64) as u32, Ordering::Relaxed);
            } else {
                blind_since = None;
                BLIND_SECS.store(0, Ordering::Relaxed);
            }
            if usable != adopted {
                adopted = usable;
                if cfg.follow {
                    log::info!(
                        "{} cluster clock: master {:?}, slots {:?}, spread {:?} us",
                        if usable { "ADOPTED" } else { "DROPPED (estimate degraded)" },
                        cluster.master.map(tlink::dot11::Mac),
                        cluster.master_slots,
                        cluster.clock.spread_us()
                    );
                }
            }

            // A MASTER CHANGE IS THE EVENT TO CORRELATE AGAINST. It re-anchors the window
            // schedule every data frame depends on, and until now it was logged nowhere.
            if cfg.follow && cluster.master != last_master {
                log::info!(
                    "MASTER CHANGED: {:?} -> {:?}, slots {:?}, anchors {}, spread {:?} us, usable {}",
                    last_master.map(tlink::dot11::Mac),
                    cluster.master.map(tlink::dot11::Mac),
                    cluster.master_slots,
                    cluster.clock.observations(),
                    cluster.clock.spread_us(),
                    usable
                );
                last_master = cluster.master;
            }

            // Periodic heartbeat, so "discovery stopped at 04:07" can be lined up against what
            // the cluster was doing at 04:07 instead of inferred afterwards.
            if cfg.follow && last_health.elapsed() >= Duration::from_secs(15) {
                last_health = Instant::now();
                log::info!(
                    "sync health: master {:?}, anchors {}, spread {:?} us, usable {}, slots {:?}",
                    cluster.master.map(tlink::dot11::Mac),
                    cluster.clock.observations(),
                    cluster.clock.spread_us(),
                    usable,
                    cluster.master_slots
                );
                // Cumulative, not per-interval: the question is where frames go over a whole
                // session, and a rate would hide a path that produced nothing from the start.
                // 802.11 type counts first, then what the data path did with them. The pair is
                // the whole point: rx_data ~0 means no data frame ever reached us from air (a
                // radio or scheduling problem), while rx_data high with written ~0 means they
                // arrived and we threw them away (a parsing or addressing problem). Those are
                // opposite bugs and they present identically as "the peer is not discoverable".
                log::info!(
                    "rx path: air mgmt {} ctrl {} data {} | seen {} -> written {} \
                     (undecodable {} = no_radiotap {} + not_data {} + DATA {}, \
                      from_self {}, not_ours {}, write_err {})",
                    rx_mgmt, rx_ctrl, rx_data,
                    rxs.seen, rxs.written, rxs.undecodable,
                    rxs.no_radiotap, rxs.not_data, rxs.data_undecodable,
                    rxs.from_self, rxs.not_ours, rxs.write_err
                );
                // The mirror of the rx line, and the blind spot that hid this for hours: the
                // kernel handed us frames to send (tlink0 tx_packets climbing) while the Pi saw
                // no data frames on air at all. `queued` is what came off the TAP, `dp_sent` is
                // what actually reached the radio, `backlog` is what is stuck waiting for a
                // window. queued >> dp_sent with a standing backlog means the drain is starved
                // of windows, not that the radio is slow.
                log::info!(
                    "tx path: queued {} -> sent {} (backlog {}, noroute {}, dropped {}, failed {})",
                    dp_queued, dp_sent, outbound.len(), dp_noroute, dp_dropped, failed
                );
                log::info!(
                    "tx slots: awake {} asleep {} noclock {} (master slots {:?})",
                    tx_awake, tx_asleep, tx_noclock, cluster.master_slots
                );
            }

            // REACTIVE INJECTION. We just heard the master, so right now we are inside its
            // availability window on its channel — the whole cluster is awake and listening.
            // Transmit immediately: this is the window alignment a host-timestamp clock cannot
            // compute, and by the libmosey trace it is how a software stack lands its frames in
            // the window (findings 100-103). Throttled so one master burst yields a few sends.
            if cfg.reactive && heard_master && adopted {
                let now_us = epoch.elapsed().as_micros() as u64;
                if now_us.saturating_sub(last_reactive_us) >= 12_000 {
                    if let Some(t) = tundev.as_ref() {
                        enqueue_from_tun(
                            t, addr, &mut tbuf, &mut outbound, OUTBOUND_MAX,
                            &mut d11_data_seq, &mut awdl_data_seq, &mut dp_noroute, &mut dp_dropped,
                            &mut dp_queued,
                        );
                    }
                    // BEACON send, capped to beacon_min_gap_us across BOTH the reactive and
                    // scheduled paths (finding 126, shared clock last_tx_us). The in-window DATA
                    // drain below is NOT gated by this, so bulk throughput is unaffected — only the
                    // PSF/MIF flood (~90/s here vs libmosey ~7.5/s on the same radio) is cut.
                    if cfg.beacon_min_gap_us == 0
                        || now_us.saturating_sub(last_tx_us) >= cfg.beacon_min_gap_us
                    {
                        let now_tsf = tsf_anchor
                            .map(|t| t + now_us.saturating_sub(host_at_anchor_us))
                            .unwrap_or(now_us);
                        set_follow(&mut b, &cluster, addr, target_metric, now_tsf);
                        let is_mif = cfg.psf_per_mif == 0 || n % (cfg.psf_per_mif + 1) == 0;
                        let mut frame = if is_mif { b.mif(now_us) } else { b.psf(now_us) };
                        tlink::action::stamp_phy_tx_time(
                            &mut frame, tlink::dot11::MGMT_HEADER_LEN, (now_us + tx_latency_est) as u32);
                        match radio.tx(&frame, TxParams::default()) {
                            Ok(()) => { if is_mif { sent_mif += 1 } else { sent_psf += 1 } }
                            Err(e) => { failed += 1; if first_error.is_none() { first_error = Some(format!("{e:?}")); } }
                        }
                        b.advance();
                        n += 1;
                        last_tx_us = now_us;
                    }
                    // Drain queued IP (mDNS answers/announcements) into the same window. With
                    // repetition FEC each frame is sent data_repeat times, so drain fewer unique
                    // frames to keep total transmissions per window (and airtime) about constant.
                    let tp = if outbound.len() <= SMALL_BURST_MAX {
                        TxParams::default()
                    } else {
                        TxParams::bulk()
                    };
                    for _ in 0..(cfg.drain_per_window / cfg.data_repeat.max(1) as usize).max(1) {
                        let Some(f) = outbound.pop_front() else { break };
                        {
                                let now_host = epoch.elapsed().as_micros() as u64;
                                let now_tsf = tsf_anchor.map(|t| t + now_host.saturating_sub(host_at_anchor_us)).unwrap_or(now_host);
                                match (cluster.clock.is_usable(), cluster.clock.slot_at(now_tsf)) {
                                    (true, Some(sl)) if cluster.master_slots.contains(&sl) => tx_awake += 1,
                                    (true, Some(_)) => tx_asleep += 1,
                                    _ => tx_noclock += 1,
                                }
                            }
                            match radio.tx(&f, tp) {
                            Ok(()) => dp_sent += 1,
                            Err(e) => { failed += 1; if first_error.is_none() { first_error = Some(format!("{e:?}")); } }
                        }
                        // Repetition FEC: resend the same frame (same seq, Retry bit set) so the
                        // peer's duplicate-detection keeps one across our no-ARQ air loss.
                        if cfg.data_repeat > 1 && f.len() >= 2 {
                            let mut dup = f.clone();
                            dup[1] |= 0x08; // 802.11 Retry
                            for _ in 1..cfg.data_repeat {
                                if radio.tx(&dup, tp).is_ok() { dp_sent += 1; }
                            }
                        }
                    }
                    // BLOCK ACK PROBE: we just heard the master, so we are in its window — the
                    // only moment an ADDBA has a chance of landing. Originate one to the master
                    // every ~2 s and let the RX side above log whether it answers. This is the
                    // single fact that decides whether software ARQ over injection is viable.
                    if cfg.blockack {
                        if let Some(master) = cluster.master {
                            if now_us.saturating_sub(ba_last_addba_us) >= 2_000_000 {
                                ba_dialog = ba_dialog.wrapping_add(1);
                                if ba_dialog == 0 {
                                    ba_dialog = 1;
                                }
                                let ssn = d11_data_seq;
                                let f = tlink::blockack::addba_request(
                                    master, addr, ba_mgmt_seq, ba_dialog,
                                    tlink::data::DEFAULT_TID, ssn, tlink::blockack::BA_WINDOW,
                                );
                                ba_mgmt_seq = (ba_mgmt_seq + 1) & 0x0fff;
                                match radio.tx(&f, TxParams::default()) {
                                    Ok(()) => log::info!(
                                        "BLOCKACK PROBE: sent ADDBA Request to master {:?} (dialog {:#04x}, tid {}, ssn {}); resp_seen={} ack_seen={}",
                                        tlink::dot11::Mac(master), ba_dialog, tlink::data::DEFAULT_TID, ssn, ba_resp_seen, ba_ack_seen
                                    ),
                                    Err(e) => log::warn!("BLOCKACK PROBE: ADDBA tx failed: {e:?}"),
                                }
                                ba_last_addba_us = now_us;
                            }
                        }
                    }
                    last_reactive_us = now_us;
                    reactive_tx += 1;
                    *tx_by_channel.entry(current_channel).or_default() += 1;
                }
            }
        }

        // Transmit only INSIDE a window we advertise. Wait first — and if we are following the
        // cluster's channel sequence, retune to the channel of the window we are heading for,
        // so both this LISTEN's successor and the transmit below land on the channel the peer
        // actually attends. The switch is ~0.6 ms (finding 99), done once per slot transition.
        let now_host = epoch.elapsed().as_micros() as u64;
        // "now" in the master's TSF, from the latest (tsf, host) anchor; falls back to host time
        // before any TSF has been seen. Cluster queries take TSF; our own beacon schedule (`b`)
        // stays on host time. Both return deltas, which are the same to sleep on either clock.
        let now_tsf = tsf_anchor
            .map(|t| t + now_host.saturating_sub(host_at_anchor_us))
            .unwrap_or(now_host);
        let wait = if cfg.follow && adopted {
            if cfg.channel_lock {
                // Single-channel backend that cannot hop (wonder): aim ONLY at the master's
                // windows that are on our channel, so every frame lands when the peer is
                // demonstrably on it. Falls back to our own advertised window if the master
                // holds no slot on this channel.
                cluster
                    .next_master_window_on(now_tsf, current_channel)
                    .map(|(w, _slot)| w)
                    .unwrap_or_else(|| b.us_until_next_advertised_window(now_host))
            } else if cfg.follow_channels {
                if let Some((w, _slot, ch)) = cluster.next_master_window(now_tsf) {
                    if ch != current_channel {
                        match radio.set_channel(ch) {
                            Ok(()) => {
                                log::debug!("hop ch{current_channel} -> ch{ch} (slot {_slot})");
                                current_channel = ch;
                                hops += 1;
                            }
                            Err(e) => {
                                hop_fail += 1;
                                log::warn!("hop ch{current_channel} -> ch{ch} (slot {_slot}) failed: {e:?}");
                                if first_error.is_none() {
                                    first_error = Some(format!("set_channel {ch}: {e:?}"));
                                }
                            }
                        }
                    }
                    w
                } else {
                    b.us_until_next_advertised_window(now_host)
                }
            } else {
                cluster
                    .us_until_master_window(now_tsf)
                    .unwrap_or_else(|| b.us_until_next_advertised_window(now_host))
            }
        } else {
            b.us_until_next_advertised_window(now_host)
        };
        if wait > 0 {
            // The gap between windows is when the kernel's packets are collected: read the
            // tun and BUILD the frames here, but do not send them (they drain in-window).
            if let Some(t) = tundev.as_ref() {
                enqueue_from_tun(
                    t, addr, &mut tbuf, &mut outbound, OUTBOUND_MAX,
                    &mut d11_data_seq, &mut awdl_data_seq, &mut dp_noroute, &mut dp_dropped,
                            &mut dp_queued,
                );
            }
            std::thread::sleep(Duration::from_micros(wait.min(3_000)));
            continue;
        }
        let now_us = epoch.elapsed().as_micros() as u64;
        // now in the master's TSF, for the cluster/master-clock queries in this section.
        let now_tsf = tsf_anchor
            .map(|t| t + now_us.saturating_sub(host_at_anchor_us))
            .unwrap_or(now_us);
        // One frame per window visit — UNLESS channel_lock, where we deliberately blast several
        // PSFs into each on-channel window so the peer receives our sync reliably enough to hold
        // a peer-table entry (a hop-less radio has only these windows to be heard in).
        // One beacon per window: non-lock keeps SLOT_US/2. channel_lock used to skip this entirely
        // (burst PSFs on a hop-less radio) but now honours beacon_min_gap_us so the burst is not a
        // channel-hogging flood (finding 126). last_tx_us is the shared beacon clock — the reactive
        // path updates it too, so the two paths cannot each fire at their own rate.
        let beacon_min_gap = if cfg.channel_lock {
            cfg.beacon_min_gap_us
        } else {
            u64::from(tlink::beacon::SLOT_US) / 2
        };
        if cfg.follow
            && beacon_min_gap > 0
            && last_tx_us > 0
            && now_us.saturating_sub(last_tx_us) < beacon_min_gap
        {
            std::thread::sleep(Duration::from_micros(3_000));
            continue;
        }
        // Advertise the best master we know: claim self while our metric leads, else name the
        // adopted cluster's master and present as a MEMBER of it — same master address, same
        // window timeline (finding 80/89, and the AirDrop-peering finding). Relative to the
        // earlier version this no longer requires root/follow_distance to be known before it
        // will follow: without them we still name the master and sit one hop out, because
        // claiming self against a stronger master is exactly what stops Apple peering us.
        set_follow(&mut b, &cluster, addr, target_metric, now_tsf);
        let is_mif = cfg.psf_per_mif == 0 || n % (cfg.psf_per_mif + 1) == 0;
        // target_tx_time at build; phy_tx_time as late as possible, so tx_delay reflects real
        // injection latency rather than the impossible literal zero. Finding 81/82.
        let mut frame = if is_mif { b.mif(now_us) } else { b.psf(now_us) };
        let phy_us = now_us + tx_latency_est;
        tlink::action::stamp_phy_tx_time(&mut frame, tlink::dot11::MGMT_HEADER_LEN, phy_us as u32);
        let tx_start = Instant::now();
        let tx_result = radio.tx(&frame, TxParams::default());
        let tx_dur = tx_start.elapsed().as_micros() as u64;
        tx_latency_est = (tx_latency_est * 7 + tx_dur) / 8;
        tx_latency_seen = tx_latency_seen.max(tx_dur);
        match tx_result {
            Ok(()) => {
                if is_mif {
                    sent_mif += 1
                } else {
                    sent_psf += 1
                }
                *tx_by_channel.entry(current_channel).or_default() += 1;
                if let Some(sl) = cluster.clock.slot_at(now_tsf) {
                    *tx_by_slot.entry(sl).or_default() += 1;
                }
            }
            Err(e) => {
                failed += 1;
                if first_error.is_none() {
                    first_error = Some(format!("{e:?}"));
                }
            }
        }
        // In-window drain: the beacon just went out, so the peer is listening now. A SMALL burst
        // (control/handshake frames — the startup /Discover, /Ask, TLS and 200 responses) is sent
        // redundantly so a single lost frame does not cost a multi-second RTO stall at setup
        // (finding 113); a large burst is bulk data, sent once to avoid channel contention (which
        // repeating was shown to add, finding 110). data_repeat, if set, still applies to bulk.
        let small_burst = outbound.len() <= SMALL_BURST_MAX;
        let reps: u32 = if small_burst { ACK_REPEAT } else { cfg.data_repeat.max(1) };
        // Same split for the rate: control keeps the pinned legacy OFDM rate (what stock uses
        // for its mDNS), bulk goes at the interface's configured VHT rate. Pinning bulk is what
        // held us at 6 Mb/s unaggregated — see TxParams::legacy_ofdm.
        let tp = if small_burst { TxParams::default() } else { TxParams::bulk() };
        for _ in 0..(cfg.drain_per_window / reps as usize).max(1) {
            let Some(f) = outbound.pop_front() else { break };
            {
                                let now_host = epoch.elapsed().as_micros() as u64;
                                let now_tsf = tsf_anchor.map(|t| t + now_host.saturating_sub(host_at_anchor_us)).unwrap_or(now_host);
                                match (cluster.clock.is_usable(), cluster.clock.slot_at(now_tsf)) {
                                    (true, Some(sl)) if cluster.master_slots.contains(&sl) => tx_awake += 1,
                                    (true, Some(_)) => tx_asleep += 1,
                                    _ => tx_noclock += 1,
                                }
                            }
                            match radio.tx(&f, tp) {
                Ok(()) => dp_sent += 1,
                Err(e) => {
                    failed += 1;
                    if first_error.is_none() {
                        first_error = Some(format!("{e:?}"));
                    }
                }
            }
            if reps > 1 && f.len() >= 2 && f.len() <= CONTROL_FRAME_MAX {
                let mut dup = f.clone();
                dup[1] |= 0x08; // 802.11 Retry; the peer de-duplicates on sequence number
                for _ in 1..reps {
                    if radio.tx(&dup, tp).is_ok() {
                        dp_sent += 1;
                    }
                }
            }
        }

        b.advance();
        n += 1;
        last_tx_us = epoch.elapsed().as_micros() as u64;
        // In channel_lock we burst within the on-channel window: a short inter-frame gap, and the
        // loop stops on its own when next_master_window_on reports the window has passed. Normally,
        // pace by the PSF interval.
        let gap_us = if cfg.channel_lock {
            8_000
        } else {
            b.psf_interval_us() / u64::from(cfg.per_window.max(1))
        };
        std::thread::sleep(Duration::from_micros(gap_us));
    }

    if cfg.follow_channels {
        log::info!("tx by channel: {tx_by_channel:?}");
        log::info!("tx by slot: {tx_by_slot:?} (master slots {:?})", cluster.master_slots);
    }
    if cfg.reactive {
        log::info!("reactive injections (on hearing the master): {reactive_tx}");
    }

    Ok(Stats {
        sent_mif,
        sent_psf,
        failed,
        tx_latency_est,
        tx_latency_seen,
        adopters: cluster.adopters.len(),
        adoption_frames: cluster.adoption_frames(),
        adopter_list: cluster.adopters.iter().map(|(m, n)| (*m, *n)).collect(),
        datapath: tundev.is_some(),
        dp_sent,
        dp_recvd,
        dp_noroute,
        dp_dropped,
        outbound_len: outbound.len(),
        rx_mgmt,
        rx_ctrl,
        rx_data,
        anchors: cluster.clock.observations(),
        master: cluster.master,
        phase_us: cluster.clock.phase_us(),
        spread_us: cluster.clock.spread_us(),
        master_changes: cluster.master_changes,
        adopted,
        hops,
        hop_fail,
        first_error,
    })
}

/// Point the beacon at the cluster's master (address, relay data, projected AW counter) when
/// one leads us, else claim self. Shared by the scheduled and reactive transmit paths so both
/// advertise the same cluster membership.
fn set_follow(
    b: &mut Beacon,
    cluster: &Cluster,
    addr: [u8; 6],
    target_metric: u32,
    now_tsf: u64,
) {
    match (cluster.master, cluster.master_metric) {
        (Some(m), Some(mm)) if m != addr && mm > target_metric => {
            b.follow = Some(FollowAdvert {
                root: cluster.root.unwrap_or(m),
                parent: cluster.relay_parent.unwrap_or(m),
                distance: cluster.follow_distance.unwrap_or(1),
                master_metric: mm,
                master_counter: cluster.master_counter.unwrap_or(0),
            });
            b.follow_master = Some(m);
            b.follow_aw_counter = cluster.projected_master_counter(now_tsf);
        }
        _ => {
            b.follow = None;
            b.follow_master = None;
            b.follow_aw_counter = None;
        }
    }
}

/// 802.11 frame type (0 = management, 1 = control, 2 = data) of a radiotap-prefixed frame.
fn frame_type(bytes: &[u8]) -> Option<u8> {
    use tlink::radiotap::Radiotap;
    let body = Radiotap::parse(bytes)?.payload(bytes)?;
    tlink::dot11::FrameControl::parse(body).map(|fc| fc.frame_type)
}

/// Parse an AWDL action frame into (src, sync params, election v2, OpClass channel sequence).
///
/// The channel sequence is the standalone tag 18 (OpClass), kept separate from the Legacy one
/// inside Sync Params: tag 18 carries the primary 20 MHz channel we can actually tune to,
/// where the Legacy channel byte is a 40 MHz centre (finding 99).
/// Where received data frames go, counted at every stage they can be lost.
///
/// Added because `tlink0` read `rx_packets=7` against `tx_packets=113` for a whole session
/// while the cluster clock was locked to a peer at 5 us spread — so the radio was plainly
/// receiving that peer's ACTION frames while its DATA frames reached nothing. Between "the
/// monitor socket returned a frame" and "the kernel got it" there were four places a frame
/// could vanish and no way to tell which, so a dead receive path and an idle one looked
/// identical. These distinguish them.
#[derive(Default, Clone, Copy)]
struct RxStages {
    /// Offered to the data path at all.
    seen: u64,
    /// Anything that did not decapsulate, for continuity with the old figure. The three
    /// counters below say WHICH, because the old single number could not.
    undecodable: u64,
    /// The radiotap header itself did not parse, so we never saw an 802.11 frame at all.
    no_radiotap: u64,
    /// Decapsulation failed on a frame that is NOT data — a beacon or action frame. Expected:
    /// every frame on the channel is offered here. Counted only so it stops inflating the
    /// number that matters.
    not_data: u64,
    /// Decapsulation failed on a DATA frame. THIS is the one that costs a transfer, and it was
    /// invisible inside `undecodable`.
    data_undecodable: u64,
    /// Our own injected frame, echoed back by the monitor. Expected and harmless; counted
    /// because it inflates any naive "frames received" figure.
    from_self: u64,
    /// Unicast to some other peer.
    not_ours: u64,
    /// Handed to the kernel.
    written: u64,
    write_err: u64,
}

/// True the first time this MAC is seen, false ever after.
///
/// Only for logging a peer's fixed capabilities once instead of on every frame. Process-local
/// and never pruned: it holds at most a handful of MACs for the life of the session, and a peer
/// that leaves and returns with the same MAC does not need its capabilities reprinted.
fn first_time_seeing(mac: [u8; 6]) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<[u8; 6]>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map(|mut s| s.insert(mac))
        // A poisoned lock here must not cost a frame: say "already seen" and stay quiet.
        .unwrap_or(false)
}

fn parse_awdl(
    bytes: &[u8],
) -> Option<(
    [u8; 6],
    tlink::sync::SyncParams,
    Option<tlink::election::ElectionParamsV2>,
    Option<tlink::sync::ChannelSequence>,
    u32,
)> {
    use tlink::{action::ActionFrame, dot11::Dot11, election::ElectionParamsV2, radiotap::Radiotap,
                  sync::{ChannelSequence, SyncParams}, tlv};
    let rt = Radiotap::parse(bytes)?;
    let body = rt.payload(bytes)?;
    let d = Dot11::parse(body)?;
    if !d.is_action() {
        return None;
    }
    let af = ActionFrame::parse(body.get(d.body_offset..)?)?;
    let (mut sync, mut elect, mut chanseq) = (None, None, None);
    for t in tlv::Tlvs::new(af.tagged) {
        match t.tag {
            4 => sync = SyncParams::parse(t.value),
            // Tag 7 = HT Capabilities. We decode this type everywhere else and have never
            // looked at it here, which is why every TxParams in the tree is a constant chosen
            // before any peer exists (tlink-shim lib.rs:171, nss: 2) while stock rate-adapts.
            //
            // LOGGED, NOT ACTED ON, deliberately. rx_mcs_bitmap is the deciding field: in HT,
            // MCS 0-7 is one spatial stream and 8-15 is two. If a peer advertises 0x00FF it
            // cannot decode our nss=2 at all; if 0xFFFF the stream count is not its problem
            // and the gap is rate adaptation. Nobody has read this from a real iPhone yet, so
            // changing the transmit rate now would be guessing — and the rate is radio-wide,
            // so a wrong guess degrades the peers that currently work.
            7 => {
                // ONCE PER PEER, NOT ONCE PER FRAME. A peer's HT capabilities do not change
                // between frames, so logging them on every parse said nothing new ~19 times a
                // second and buried everything that mattered: it was 39% of all logcat lines,
                // and it hid both a transfer's own timestamps and an SELinux denial during
                // diagnosis. debug! as well as deduplicated — this is a bring-up detail, and
                // info! is what an operator reads when something is wrong.
                if let Some(ht) = tlink::state::HtCapabilities::parse(t.value) {
                    if first_time_seeing(d.src.0) {
                        log::debug!(
                            "peer {} HT caps: rx_mcs_bitmap=0x{:04x} info=0x{:04x} ampdu=0x{:02x} \
                             (MCS 8-15 set => 2 spatial streams)",
                            tlink::dot11::Mac(d.src.0),
                            ht.rx_mcs_bitmap,
                            ht.info,
                            ht.ampdu_params
                        );
                    }
                }
            }
            18 => chanseq = ChannelSequence::parse(t.value),
            24 => elect = ElectionParamsV2::parse(t.value),
            _ => {}
        }
    }
    Some((d.src.0, sync?, elect, chanseq, af.fixed.phy_tx_time))
}

// --- data path -------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_datapath(
    name: Option<&str>,
    addr: [u8; 6],
) -> Result<Option<tlink_hal::tun::Tun>> {
    let Some(name) = name else { return Ok(None) };
    let t = tlink_hal::tun::Tun::open(name)?;
    match t.configure(addr) {
        Ok(a) => log::info!("datapath {name}: up on {a}, IPv6 queued and drained in-window"),
        Err(e) => {
            return Err(Error::Radio(format!(
                "datapath {name}: opened but NOT configured: {e:?} — it carries no address, \
                 so nothing will flow"
            )))
        }
    }
    Ok(Some(t))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_datapath(name: Option<&str>, _addr: [u8; 6]) -> Result<Option<()>> {
    if name.is_some() {
        return Err(Error::Unsupported("a data path needs /dev/net/tun (Linux/Android only)"));
    }
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(clippy::too_many_arguments)]
fn enqueue_from_tun(
    tun: &tlink_hal::tun::Tun,
    our_mac: [u8; 6],
    buf: &mut [u8],
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    max: usize,
    d11_seq: &mut u16,
    awdl_seq: &mut u16,
    unroutable: &mut u64,
    dropped: &mut u64,
    queued: &mut u64,
) {
    use tlink::data::{dst_mac_for_ipv6, Encap, ETHERTYPE_IPV6};
    use tlink_hal::poll::wait_readable;
    use std::os::fd::AsRawFd;

    // Read up to a window's worth of segments per cycle so a bulk TCP burst actually reaches
    // the queue (was 4, which throttled /Upload to a trickle). Bounded by the queue's free
    // space: once it is full we stop reading and leave the rest in the kernel, which is what
    // makes TCP flow-control the sender instead of us silently dropping in-flight segments.
    for _ in 0..DRAIN_PER_WINDOW {
        if queue.len() >= max {
            return; // backpressure: let the tun/kernel hold it; do not drop TCP data
        }
        match wait_readable(tun.as_raw_fd(), tun.as_raw_fd(), 0) {
            Ok(r) if r.first => {}
            _ => return,
        }
        let n = match tun.read(buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        // The interface is a TAP, so this is an Ethernet frame: strip the 14-byte header and
        // encapsulate only IPv6 (ethertype 0x86dd). ARP/IPv4 and runts are dropped.
        let frame_bytes = &buf[..n];
        if frame_bytes.len() < 14 || frame_bytes[12] != 0x86 || frame_bytes[13] != 0xdd {
            continue;
        }
        let pkt = &frame_bytes[14..];
        let Some(dst) = dst_mac_for_ipv6(pkt) else {
            *unroutable += 1;
            continue;
        };
        let frame = Encap::unicast(our_mac, dst).frame(*d11_seq, *awdl_seq, ETHERTYPE_IPV6, pkt);
        *d11_seq = (*d11_seq + 1) & 0x0fff;
        *awdl_seq = awdl_seq.wrapping_add(1);
        // Space was checked at the top of the loop, so this never exceeds `max`. We do not drop
        // here: a dropped TCP segment stalls the whole transfer (no link-layer retransmit). The
        // `dropped` counter therefore stays 0 now, which honestly reflects the backpressure path.
        queue.push_back(frame);
        *queued += 1;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn deliver_data_frame(
    bytes: &[u8],
    our_mac: [u8; 6],
    tun: Option<&tlink_hal::tun::Tun>,
    delivered: &mut u64,
    st: &mut RxStages,
) {
    use tlink::data::{decapsulate_all, is_ipv6_multicast};
    use tlink::radiotap::Radiotap;

    st.seen += 1;
    let Some(tun) = tun else { return };
    // ONE COUNTER FOR FOUR DIFFERENT THINGS WAS THE PROBLEM. `undecodable` lumped together a
    // beacon (expected, every frame on the channel comes through here) and a data frame we
    // could not parse (a bug, and the only one that costs a transfer). Measured 2026-09-26 on
    // a stalled 20 MB send: seen 6548, mgmt 5467, data 1081, written 579, undecodable 5969 —
    // so 502 DATA frames were thrown away, which is the ~50% loss TCP was reporting. Whether
    // those were our peer's frames or an Apple device's that we simply do not parse cannot be
    // told from one number, and the answer changes the diagnosis completely. So: count the
    // stages apart.
    let Some(dot11) = Radiotap::parse(bytes).and_then(|rt| rt.payload(bytes)) else {
        st.no_radiotap += 1;
        st.undecodable += 1;
        return;
    };
    // EVERY packet in the frame, not the first: under load the radio aggregates several
    // MSDUs into one 802.11 frame, and taking only the head silently drops the rest.
    let packets = decapsulate_all(dot11);
    if packets.is_empty() {
        st.undecodable += 1;
        // A management frame failing here is normal and says nothing. A DATA frame failing
        // here is the interesting case, so name it and keep the source, because "our peer" and
        // "some iPhone whose format we do not read" are opposite conclusions.
        match tlink::dot11::FrameControl::parse(dot11) {
            Some(fc) if fc.frame_type == tlink::dot11::TYPE_DATA => {
                st.data_undecodable += 1;
                if let Some(src) = dot11.get(10..16) {
                    let mac: [u8; 6] = src.try_into().unwrap_or_default();
                    if st.data_undecodable % 64 == 1 {
                        // LENGTH IS THE POINT OF THIS LINE. If every failure is a long frame,
                        // the capture is truncating and only bulk payload is being lost —
                        // which is exactly what a transfer that stalls while control traffic
                        // keeps flowing looks like. If the lengths are mixed, it is a header
                        // we misparse. Those need different fixes and a counter cannot tell
                        // them apart, so print the size, the subtype and the bytes where the
                        // SNAP header should be.
                        log::warn!(
                            "rx: data frame from {mac:02x?} did not decapsulate ({} so far) — \
                             len {} subtype {:#04x} head {:02x?}",
                            st.data_undecodable,
                            dot11.len(),
                            fc.subtype,
                            dot11.get(..40).unwrap_or(dot11)
                        );
                    }
                }
            }
            _ => st.not_data += 1,
        }
        return;
    }
    for d in packets {
    // Split rather than combined: "our own frame echoed back by the monitor" and "unicast to
    // somebody else" are different failures with different fixes, and lumping them together is
    // what made a dead receive path look like a quiet one.
    if d.src == our_mac {
        st.from_self += 1;
        continue;
    }
    if d.dst != our_mac && !is_ipv6_multicast(d.dst) {
        st.not_ours += 1;
        continue;
    }
    // The interface is a TAP, so the kernel expects an Ethernet frame. Prepend a 14-byte
    // header: destination is our MAC for unicast, or the 33:33-mapped multicast MAC for a
    // multicast IPv6 destination (mDNS ff02::fb), so the kernel actually delivers it.
    let ip = d.payload;
    let eth_dst: [u8; 6] = if ip.len() >= 40 && ip[24] == 0xff {
        [0x33, 0x33, ip[36], ip[37], ip[38], ip[39]]
    } else {
        our_mac
    };
    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&d.src);
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(ip);
    if tun.write(&frame).is_ok() {
        *delivered += 1;
        st.written += 1;
    } else {
        st.write_err += 1;
    }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[allow(clippy::too_many_arguments)]
fn enqueue_from_tun(
    _t: &(), _m: [u8; 6], _b: &mut [u8],
    _q: &mut std::collections::VecDeque<Vec<u8>>, _max: usize,
    _d: &mut u16, _a: &mut u16, _u: &mut u64, _dr: &mut u64, _q: &mut u64,
) {
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn deliver_data_frame(
    _bytes: &[u8], _our_mac: [u8; 6], _tun: Option<&()>, _delivered: &mut u64, _st: &mut RxStages,
) {
}