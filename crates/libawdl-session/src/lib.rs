//! The held AWDL session: one loop that listens, keeps the cluster clock, transmits in the
//! windows it advertises, and carries the data path — over any [`libawdl_hal::Radio`].
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

use libawdl::beacon::{Beacon, FollowAdvert, Garbage};
use libawdl::follow::Cluster;
use libawdl_hal::{Error, Radio, Result, TxParams};

/// How the session should behave. The knobs that were CLI flags.
pub struct Config {
    pub channel: u8,
    pub country: [u8; 2],
    /// One MIF (full frame) per this many PSFs. 0 = every frame a MIF.
    pub psf_per_mif: u32,
    /// Announce [`libawdl::beacon::METRIC_COMPETE`].
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
    pub tenure: Option<u32>,
    pub legacy_timing: bool,
    pub version: Option<(u8, u8)>,
    pub garbage: Option<Garbage>,
    /// Name of a TUN to bring up and carry IP over (e.g. `tawdl0`). None = control plane only.
    pub datapath: Option<String>,
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
            tenure: None,
            legacy_timing: false,
            version: None,
            garbage: None,
            datapath: None,
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
    pub first_error: Option<String>,
}

/// Bounded outbound queue: a burst the radio cannot keep up with must not grow without limit,
/// and on a windowed link the stale end is the part worth dropping.
const OUTBOUND_MAX: usize = 64;
/// Data frames drained per window visit. A beacon plus a few data frames fits an extended
/// window; emptying a full queue into one window overruns into the next slot.
const DRAIN_PER_WINDOW: usize = 4;

/// Run the session on `radio` (already brought up) until `stop` is set or `cfg.duration`
/// elapses. Returns what it did.
pub fn run(radio: &mut dyn Radio, cfg: &Config, stop: &AtomicBool) -> Result<Stats> {
    let addr = radio.mac_address()?;
    let mut b = Beacon::new(addr, cfg.channel, core::str::from_utf8(&cfg.country).unwrap_or("QA"));

    if let Some((major, minor)) = cfg.version {
        b.version = libawdl::state::Version { major, minor, device_class: 2 };
    }
    log::info!("announcing AWDL v{}.{}", b.version.major, b.version.minor);

    let mut cluster = Cluster::for_us(addr);
    let mut adopted = false;

    // Data plane: the TUN shares this loop and this radio (two processes cannot both inject
    // on one phy). Outbound IP is queued and drained in-window, because an AWDL peer listens
    // only during its availability windows.
    let tundev = open_datapath(cfg.datapath.as_deref(), addr)?;
    let mut outbound: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut tbuf = vec![0u8; 4096];
    let (mut dp_sent, mut dp_recvd, mut dp_noroute, mut dp_dropped) = (0u64, 0u64, 0u64, 0u64);
    let (mut rx_mgmt, mut rx_ctrl, mut rx_data) = (0u64, 0u64, 0u64);
    let mut awdl_data_seq: u16 = 0;
    let mut d11_data_seq: u16 = 0;

    if cfg.compete {
        b.metric = libawdl::beacon::METRIC_COMPETE;
    }
    if let Some(m) = cfg.metric {
        b.metric = m;
    }
    // --metric-floor: announce the decline metric first, then step. This is what Apple does
    // (finding 77) — the floor is a claim about being a credible timing anchor.
    let target_metric = b.metric;
    let floor_until = cfg.metric_floor.map(|s| Instant::now() + Duration::from_secs(s));
    if cfg.metric_floor.is_some() {
        b.metric = libawdl::beacon::METRIC_DECLINE;
    }
    if let Some(t) = cfg.tenure {
        b.tenure_base = t;
    }
    if let Some(w) = cfg.windows {
        b.windows = Some(w);
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
                let now_us = epoch.elapsed().as_micros() as u64;
                match cluster.us_until_master_window(now_us) {
                    Some(w) if adopted => w,
                    _ => b.us_until_next_advertised_window(now_us),
                }
            };
            let budget_ms = if slack_us < 4_000 { 0 } else { 2 };
            let max_drain = if slack_us < 4_000 { 4 } else { 32 };

            let mut drained = 0;
            while drained < max_drain {
                if let Ok(Some(rx)) = radio.rx(if drained == 0 { budget_ms } else { 0 }) {
                    drained += 1;
                    // The kernel's arrival time, not ours: a socket backlog otherwise gets
                    // added to every frame behind it.
                    let now_us = rx
                        .host_us
                        .map(|t| t.saturating_sub(epoch_realtime_us))
                        .unwrap_or_else(|| epoch.elapsed().as_micros() as u64);
                    match frame_type(&rx.bytes) {
                        Some(2) => rx_data += 1,
                        Some(1) => rx_ctrl += 1,
                        Some(_) => rx_mgmt += 1,
                        None => {}
                    }
                    if tundev.is_some() {
                        deliver_data_frame(&rx.bytes, addr, tundev.as_ref(), &mut dp_recvd);
                    }
                    if let Some((src, sync, elect)) = parse_awdl(&rx.bytes) {
                        // Never synchronise to our own transmissions handed back by the monitor.
                        if src != addr {
                            cluster.observe(now_us, src, &sync, elect.as_ref());
                        }
                    }
                } else {
                    break;
                }
            }
            let usable = cluster.clock.is_usable();
            if usable != adopted {
                adopted = usable;
                if cfg.follow {
                    log::info!(
                        "{} cluster clock: master {:?}, slots {:?}, spread {:?} us",
                        if usable { "ADOPTED" } else { "DROPPED (estimate degraded)" },
                        cluster.master.map(libawdl::dot11::Mac),
                        cluster.master_slots,
                        cluster.clock.spread_us()
                    );
                }
            }
        }

        // Transmit only INSIDE a window we advertise. Wait first.
        let now_us = epoch.elapsed().as_micros() as u64;
        let wait = match cluster.us_until_master_window(now_us) {
            Some(w) if cfg.follow && adopted => w,
            _ => b.us_until_next_advertised_window(now_us),
        };
        if wait > 0 {
            // The gap between windows is when the kernel's packets are collected: read the
            // tun and BUILD the frames here, but do not send them (they drain in-window).
            if let Some(t) = tundev.as_ref() {
                enqueue_from_tun(
                    t, addr, &mut tbuf, &mut outbound, OUTBOUND_MAX,
                    &mut d11_data_seq, &mut awdl_data_seq, &mut dp_noroute, &mut dp_dropped,
                );
            }
            std::thread::sleep(Duration::from_micros(wait.min(3_000)));
            continue;
        }
        let now_us = epoch.elapsed().as_micros() as u64;
        // One frame per window visit.
        if cfg.follow
            && last_tx_us > 0
            && now_us.saturating_sub(last_tx_us) < u64::from(libawdl::beacon::SLOT_US) / 2
        {
            std::thread::sleep(Duration::from_micros(3_000));
            continue;
        }
        // Advertise the best master we know: claim self while our metric leads, else name the
        // adopted peer and place ourselves one hop out (finding 80/89).
        b.follow = match (cluster.master, cluster.master_metric, cluster.root, cluster.follow_distance) {
            (Some(m), Some(mm), Some(root), Some(dist)) if m != addr && mm > target_metric => {
                Some(FollowAdvert {
                    root,
                    parent: cluster.relay_parent.unwrap_or(root),
                    distance: dist,
                    master_metric: mm,
                    master_counter: cluster.master_counter.unwrap_or(0),
                })
            }
            _ => None,
        };
        let is_mif = cfg.psf_per_mif == 0 || n % (cfg.psf_per_mif + 1) == 0;
        // target_tx_time at build; phy_tx_time as late as possible, so tx_delay reflects real
        // injection latency rather than the impossible literal zero. Finding 81/82.
        let mut frame = if is_mif { b.mif(now_us) } else { b.psf(now_us) };
        let phy_us = now_us + tx_latency_est;
        libawdl::action::stamp_phy_tx_time(&mut frame, libawdl::dot11::MGMT_HEADER_LEN, phy_us as u32);
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
            }
            Err(e) => {
                failed += 1;
                if first_error.is_none() {
                    first_error = Some(format!("{e:?}"));
                }
            }
        }
        // In-window drain: the beacon just went out, so the peer is listening now.
        for _ in 0..DRAIN_PER_WINDOW {
            let Some(f) = outbound.pop_front() else { break };
            match radio.tx(&f, TxParams::default()) {
                Ok(()) => dp_sent += 1,
                Err(e) => {
                    failed += 1;
                    if first_error.is_none() {
                        first_error = Some(format!("{e:?}"));
                    }
                }
            }
        }

        b.advance();
        n += 1;
        last_tx_us = epoch.elapsed().as_micros() as u64;
        std::thread::sleep(Duration::from_micros(
            b.psf_interval_us() / u64::from(cfg.per_window.max(1)),
        ));
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
        first_error,
    })
}

/// 802.11 frame type (0 = management, 1 = control, 2 = data) of a radiotap-prefixed frame.
fn frame_type(bytes: &[u8]) -> Option<u8> {
    use libawdl::radiotap::Radiotap;
    let body = Radiotap::parse(bytes)?.payload(bytes)?;
    libawdl::dot11::FrameControl::parse(body).map(|fc| fc.frame_type)
}

/// Parse an AWDL action frame into (src, sync params, election v2).
fn parse_awdl(
    bytes: &[u8],
) -> Option<([u8; 6], libawdl::sync::SyncParams, Option<libawdl::election::ElectionParamsV2>)> {
    use libawdl::{action::ActionFrame, dot11::Dot11, election::ElectionParamsV2, radiotap::Radiotap,
                  sync::SyncParams, tlv};
    let rt = Radiotap::parse(bytes)?;
    let body = rt.payload(bytes)?;
    let d = Dot11::parse(body)?;
    if !d.is_action() {
        return None;
    }
    let af = ActionFrame::parse(body.get(d.body_offset..)?)?;
    let (mut sync, mut elect) = (None, None);
    for t in tlv::Tlvs::new(af.tagged) {
        match t.tag {
            4 => sync = SyncParams::parse(t.value),
            24 => elect = ElectionParamsV2::parse(t.value),
            _ => {}
        }
    }
    Some((d.src.0, sync?, elect))
}

// --- data path -------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_datapath(
    name: Option<&str>,
    addr: [u8; 6],
) -> Result<Option<libawdl_hal::tun::Tun>> {
    let Some(name) = name else { return Ok(None) };
    let t = libawdl_hal::tun::Tun::open(name)?;
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
    tun: &libawdl_hal::tun::Tun,
    our_mac: [u8; 6],
    buf: &mut [u8],
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    max: usize,
    d11_seq: &mut u16,
    awdl_seq: &mut u16,
    unroutable: &mut u64,
    dropped: &mut u64,
) {
    use libawdl::data::{dst_mac_for_ipv6, Encap, ETHERTYPE_IPV6};
    use libawdl_hal::poll::wait_readable;
    use std::os::fd::AsRawFd;

    for _ in 0..4 {
        match wait_readable(tun.as_raw_fd(), tun.as_raw_fd(), 0) {
            Ok(r) if r.first => {}
            _ => return,
        }
        let n = match tun.read(buf) {
            Ok(n) => n,
            Err(_) => return,
        };
        let pkt = &buf[..n];
        let Some(dst) = dst_mac_for_ipv6(pkt) else {
            *unroutable += 1;
            continue;
        };
        let frame = Encap::unicast(our_mac, dst).frame(*d11_seq, *awdl_seq, ETHERTYPE_IPV6, pkt);
        *d11_seq = (*d11_seq + 1) & 0x0fff;
        *awdl_seq = awdl_seq.wrapping_add(1);
        if queue.len() >= max {
            queue.pop_front();
            *dropped += 1;
        }
        queue.push_back(frame);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn deliver_data_frame(
    bytes: &[u8],
    our_mac: [u8; 6],
    tun: Option<&libawdl_hal::tun::Tun>,
    delivered: &mut u64,
) {
    use libawdl::data::{decapsulate, is_ipv6_multicast};
    use libawdl::radiotap::Radiotap;

    let Some(tun) = tun else { return };
    let Some(d) = Radiotap::parse(bytes).and_then(|rt| rt.payload(bytes)).and_then(decapsulate)
    else {
        return;
    };
    if d.src == our_mac || (d.dst != our_mac && !is_ipv6_multicast(d.dst)) {
        return;
    }
    if tun.write(d.payload).is_ok() {
        *delivered += 1;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[allow(clippy::too_many_arguments)]
fn enqueue_from_tun(
    _t: &(), _m: [u8; 6], _b: &mut [u8],
    _q: &mut std::collections::VecDeque<Vec<u8>>, _max: usize,
    _d: &mut u16, _a: &mut u16, _u: &mut u64, _dr: &mut u64,
) {
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn deliver_data_frame(_bytes: &[u8], _our_mac: [u8; 6], _tun: Option<&()>, _delivered: &mut u64) {}
