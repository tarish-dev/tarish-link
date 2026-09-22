//! A drop-in replacement for `libmosey_daemon_ffi.so`, backed by our own AWDL stack.
//!
//! `tarishd` brings AWDL up by `dlopen`-ing a library and calling `mosey_start_5`, then
//! holds the returned handle for the life of the session and `mosey_stop`s it at the end
//! (see `tarish-daemon/src/mosey.rs`). Point `TARISH_MOSEY_LIB` at this `.so` and the daemon
//! runs over `tlink` + the `wonder` backend instead of Google's library — it does its own
//! mDNS, TLS and transfers on top, unchanged.
//!
//! Only `mosey_start_5` and `mosey_stop` are actually bound by `tarishd`; the rest are
//! harmless stubs for any other caller.
//!
//! The data interface is **`tlink0`** (not `mosey0` and not Apple's `awdl0`). `tarishd` must
//! be told that name — it reads `persist.tarish.iface` / `$TARISH_IFACE`.

// The wonder backend and AF_PACKET are Linux/Android only; on a dev host this is an empty
// cdylib so the workspace still builds.
#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use tlink_hal::{wonder::Wonder, Radio, TxParams};
use tlink_session::Config;

/// The wonder monitor the backend drives.
const WONDER_IFACE: &str = "wonder0";

/// The interface the session's data path is carried on — the same name `tarishd` is pointed
/// at (`persist.tarish.iface`). Defaults to `tlink0`; set the property to `mosey0` to run
/// under a daemon build that still expects the old name.
fn data_iface() -> String {
    if let Ok(v) = std::env::var("TARISH_IFACE") {
        if !v.is_empty() {
            return v;
        }
    }
    read_property("persist.tarish.iface").unwrap_or_else(|| "tlink0".to_string())
}

#[cfg(target_os = "android")]
fn read_property(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = [0u8; 128];
    // SAFETY: cname is NUL-terminated and buf is >= PROP_VALUE_MAX.
    let n = unsafe {
        libc::__system_property_get(cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char)
    };
    if n <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..n as usize]).ok().map(|s| s.to_string())
}

#[cfg(not(target_os = "android"))]
fn read_property(_name: &str) -> Option<String> {
    None
}

/// Opaque session handle handed back to `tarishd`. The session lives exactly as long as this
/// value — `mosey_stop` drops it, which signals the loop and tears the radio and TUN down.
struct Shim {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(target_os = "android")]
fn init_log() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("tarish_awdl")
                .with_max_level(log::LevelFilter::Info),
        );
    });
}

#[cfg(not(target_os = "android"))]
fn init_log() {}

/// `void *mosey_start_5(channels, n_channels, max_mdns, country, op_mode, config, config_len)`
///
/// Signature and argument order match `tarishd`'s `Start5` binding exactly. Returns an opaque
/// handle, or NULL on failure (the daemon logs and retries, as it does for the real library).
///
/// # Safety
/// `channels` and `country` must be valid pointers for their stated lengths, as they are when
/// `tarishd` calls this. `country` is a NUL-terminated 2-letter code.
/// A fresh locally-administered unicast MAC (LAA bit set, multicast bit clear), from
/// `/dev/urandom` — what Apple's own AWDL uses for each session.
#[allow(dead_code)] // kept for experiments; the AWDL address now tracks wondertap0's MAC
fn random_laa() -> [u8; 6] {
    let mut m = [0u8; 6];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut m);
    }
    m[0] = (m[0] & 0xfc) | 0x02; // locally administered, unicast
    m
}

#[no_mangle]
pub unsafe extern "C" fn mosey_start_5(
    channels: *const u8,
    n_channels: u64,
    _max_mdns: u32,
    country: *const c_char,
    op_mode: u32,
    _config: *const u8,
    _config_len: u64,
) -> *mut c_void {
    init_log();

    if op_mode != 2 {
        log::error!("mosey shim: only op_mode 2 (wonder/netlink) is supported, got {op_mode}");
        return std::ptr::null_mut();
    }
    if channels.is_null() || n_channels == 0 {
        log::error!("mosey shim: no channels given");
        return std::ptr::null_mut();
    }
    // The session holds one channel at a time. Prefer the 5 GHz social channel (149) when the
    // daemon offers it: the radio cannot hop (findings 100/101 — no hardware schedule, live
    // retune is a no-op), so the single channel we sit on has to be the one the peer attends,
    // and 149 is quieter than the 2.4 GHz social channel. Falls back to the first offered.
    // TARISH_CHANNEL overrides for experiments.
    let offered = unsafe { std::slice::from_raw_parts(channels, n_channels as usize) };
    let channel = std::env::var("TARISH_CHANNEL")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .filter(|c| offered.contains(c))
        .or_else(|| offered.contains(&149).then_some(149))
        .unwrap_or(offered[0]);
    log::info!("mosey shim: offered channels {offered:?}, sitting on ch{channel}");
    // FAIL CLOSED on the regulatory domain (security review, finding #4). No assumed country:
    // "00" is the world domain — the most restrictive — so without a real code from tarishd the
    // radio uses conservative rules rather than an arbitrary guess ("QA", which happens to allow
    // ch149). tarishd passes the SIM/locale country in normal operation; this only bites if it
    // does not, and then restricting is the correct, legal behaviour. Channel bring-up
    // separately refuses a no-initiate-radiation channel (Radio::set_regulatory / caps), so an
    // unpermitted channel is never transmitted on.
    let cc: [u8; 2] = if country.is_null() {
        *b"00"
    } else {
        let b = unsafe { CStr::from_ptr(country) }.to_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
            [b[0], b[1]]
        } else {
            *b"00" // malformed/short code → world domain, not a guessed country
        }
    };

    // Bring the radio up here, on the caller's thread, so a failure is reported synchronously
    // as NULL (which is what the daemon knows how to handle).
    let mut radio = match Wonder::new(WONDER_IFACE) {
        Ok(w) => w,
        Err(e) => {
            log::error!("mosey shim: cannot reach {WONDER_IFACE}: {e:?}");
            return std::ptr::null_mut();
        }
    };
    // Bring-up TX rate, band-aware. VHT MCS is 0..=9 — the old uniform mcs=11 is INVALID on the
    // 5 GHz VHT channels (it is an HT index), and an invalid VHT rate silently falls back to a low
    // rate, which is finding 118's ~20x throughput hole vs stock on ch149. Stock's *traced* bring-up
    // rate on ch149 is mcs=3 (VHT), and its data then rate-adapts up to MCS 9; on 2.4 GHz HT, 11 is
    // a valid HT index. So: HT(2.4) -> 11, VHT(5) -> 3 to match stock and let the firmware adapt.
    let mcs = if channel < 36 { 11 } else { 3 };
    let params = TxParams { mcs, nss: 2, bandwidth: if channel < 36 { 0 } else { 2 }, short_gi: false };
    if let Err(e) = radio.bring_up(channel, params, cc) {
        log::error!("mosey shim: wonder bring-up failed: {e:?}");
        return std::ptr::null_mut();
    }

    let iface = data_iface();
    let mut cfg = Config::new(channel, cc);
    cfg.follow = true; // participate in the cluster and sync to whoever is master
    // wonder cannot hop (findings 100/101: no live retune, no hardware schedule), so instead of
    // chasing the master across [6, 149] we LOCK to our single channel and transmit only in the
    // master's windows that are on it — bursting PSFs there so Apple peers us reliably despite
    // being present on just one social channel.
    cfg.channel_lock = true;
    // Transmit on hearing the master (provably in-window) — the window alignment a host clock
    // cannot compute, and how the libmosey trace lands frames in the window (findings 100-103).
    cfg.reactive = true;
    // Beacon (PSF/MIF) rate cap — finding 126. channel_lock + reactive together flooded the social
    // channel at ~90 frames/s; libmosey on this SAME hop-less radio peers iPhones at ~7.5/s, so the
    // "burst several PSFs per window" premise was wrong — the wondertap0-MAC trick (below) is what
    // gets us peered, not volume. The flood starved the iPhone's transmit slots so a tap took ~5s to
    // reach us as /Ask. Default 60 ms (~16/s, 2x libmosey for our looser software timing); sweep with
    // persist.tarish.beacon_gap_us / TARISH_BEACON_GAP_US (0 = old uncapped flood).
    cfg.beacon_min_gap_us = std::env::var("TARISH_BEACON_GAP_US")
        .ok()
        .or_else(|| read_property("persist.tarish.beacon_gap_us"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60_000);
    // Block Ack probe: originate an ADDBA to the master and log whether the iPhone answers, to
    // decide whether software ARQ over injection is viable (finding 105). Off unless asked.
    cfg.blockack = std::env::var("TARISH_BA_PROBE").is_ok()
        || read_property("persist.tarish.ba_probe").as_deref() == Some("1");
    // Repetition FEC for outbound data (finding 106): our inject path has no ARQ and iOS will not
    // Block-Ack us, so send each data frame N times (same seq, Retry bit) and let the peer de-dup.
    // Default 3 (~10% loss -> ~0.1%); tune with persist.tarish.data_repeat or TARISH_DATA_REPEAT.
    cfg.data_repeat = std::env::var("TARISH_DATA_REPEAT")
        .ok()
        .or_else(|| read_property("persist.tarish.data_repeat"))
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n >= 1 && n <= 8)
        .unwrap_or(3);
    // Advertise **wondertap0's** MAC as our AWDL address, not wonder0's.
    //
    // wonder0 is only the mac80211 injection shim; the actual radio is wondertap0 (bcmdhd4390),
    // which wonder.ko delegates all RF to. The Broadcom firmware auto-ACKs directed frames only
    // for the address wondertap0 owns. The iPhone opens its transfer with an 802.11 ADDBA
    // (Block Ack) handshake and sends /Discover over a directed link; those frames need a
    // link-layer ACK, which is done in firmware at SIFS and can never be a host job.
    //
    // Advertising wonder0's MAC (ce:25…) or a random LAA leaves the directed frames on an
    // address the firmware does not own, so it never ACKs and the peer retries ADDBA forever
    // (measured: ~146 retries/10s from each iPhone, no session, never shown on the share sheet).
    // Stock libmosey advertises wondertap0's MAC for exactly this reason — its mosey0 address
    // equals wondertap0's, and data then flows (stock log: data_rx_frame_count > 0). We do the
    // same. wondertap0's MAC rotates each session, so read it live rather than pinning it.
    const WONDERTAP_IFACE: &str = "wondertap0";
    match radio.mac_of(WONDERTAP_IFACE) {
        Ok(m) => {
            log::info!(
                "mosey shim: AWDL address = {WONDERTAP_IFACE} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (firmware-ACKed radio MAC)",
                m[0], m[1], m[2], m[3], m[4], m[5]
            );
            cfg.override_mac = Some(m);
        }
        Err(e) => {
            // Fall back to wonder0's MAC (override left None). This will not be ACKed, but it
            // keeps sync/advertising working and makes the cause visible rather than silent.
            log::error!("mosey shim: cannot read {WONDERTAP_IFACE} MAC ({e:?}); AWDL address falls back to wonder0 — directed frames will NOT be ACKed");
        }
    }
    cfg.datapath = Some(iface);
    // duration None: run until mosey_stop.

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut radio = radio;
        log::info!("mosey shim: session starting on ch{channel} cc={}{}", cc[0] as char, cc[1] as char);
        // Catch a panic in the session (security review, finding #7). Without this a panic
        // unwinds the thread silently: mosey_stop's join ignores the error and tarishd keeps
        // believing the AWDL link is up. Turn it into a loud, distinct error so a crash in
        // parsing/timing surfaces instead of a link that is dead but reported live.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tlink_session::run(&mut radio, &cfg, &stop_thread)
        }));
        match outcome {
            Ok(Ok(s)) => log::info!(
                "mosey shim: session ended — {} MIF/{} PSF sent, {} data delivered",
                s.sent_mif, s.sent_psf, s.dp_recvd
            ),
            Ok(Err(e)) => log::error!("mosey shim: session error: {e:?}"),
            Err(_) => log::error!(
                "mosey shim: SESSION PANICKED — AWDL link is DOWN. tarishd should restart it."
            ),
        }
    });

    let shim = Box::new(Shim { stop, thread: Some(thread) });
    Box::into_raw(shim) as *mut c_void
}

/// `void *mosey_stop(void *handle)` — stop the session and tear it down. Returns NULL.
///
/// # Safety
/// `handle` must be a value previously returned by [`mosey_start_5`], or NULL.
#[no_mangle]
pub unsafe extern "C" fn mosey_stop(handle: *mut c_void) -> *mut c_void {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: handle came from Box::into_raw in mosey_start_5 and is not used again.
    let mut shim = unsafe { Box::from_raw(handle as *mut Shim) };
    shim.stop.store(true, Ordering::Relaxed);
    if let Some(t) = shim.thread.take() {
        let _ = t.join();
    }
    // Release the chip's single Wi-Fi P2P slot for an off-network Quick Share Wi-Fi Direct
    // group. Dropping the session (above) frees `tlink0` but leaves `wondertap0` — the
    // `WL_IF_TYPE_ART` monitor — registered, so the driver still refuses a `P2P_GO`. Downing
    // wondertap0 makes it `del_iface` + `dhd_monitor_stop`, which releases the ART role;
    // wonder0 follows for a clean teardown. `mosey_start_5` recreates both, so this is safe on
    // every stop. Best-effort — a missing iface or denied SETLINK is logged, not fatal.
    // Validated on a Pixel 10 Pro (blazer) 2026-09-22; see docs/COEXISTENCE.md.
    if let Err(e) = tlink_hal::wonder::set_iface_down("wondertap0") {
        log::warn!("mosey shim: could not down wondertap0 on stop ({e:?}); P2P slot may stay held");
    }
    if let Err(e) = tlink_hal::wonder::set_iface_down(WONDER_IFACE) {
        log::warn!("mosey shim: could not down {WONDER_IFACE} on stop ({e:?})");
    }
    log::info!("mosey shim: session stopped (AWDL torn down, P2P slot released)");
    std::ptr::null_mut()
}

// --- stubs, for ABI completeness (tarishd binds only start_5 and stop) -----------------

/// # Safety
/// FFI stub; arguments are ignored.
#[no_mangle]
pub unsafe extern "C" fn mosey_update(
    _handle: *mut c_void,
    _a: u64,
    _b: u64,
    _c: u64,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// # Safety
/// FFI stub; the argument is ignored.
#[no_mangle]
pub unsafe extern "C" fn mosey_reset(_which: u8) {}

/// # Safety
/// FFI stub.
#[no_mangle]
pub unsafe extern "C" fn mosey_dump() {
    log::info!("mosey shim: dump (no state exported)");
}

/// `const char *mosey_version(void)` — the tlink shim's version, so `tarishd` can report
/// the AWDL stack's version to the app. NOT part of Google's libmosey ABI: it is an
/// addition of ours, so the daemon must `dlsym` it and treat its absence as "unknown"
/// (an older pin, or the real libmosey, will not export it).
///
/// # Safety
/// Returns a pointer to a static NUL-terminated string, valid for the process lifetime.
#[no_mangle]
pub unsafe extern "C" fn mosey_version() -> *const std::os::raw::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::os::raw::c_char
}
