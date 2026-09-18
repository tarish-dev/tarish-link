//! A drop-in replacement for `libmosey_daemon_ffi.so`, backed by our own AWDL stack.
//!
//! `tarishd` brings AWDL up by `dlopen`-ing a library and calling `mosey_start_5`, then
//! holds the returned handle for the life of the session and `mosey_stop`s it at the end
//! (see `tarish-daemon/src/mosey.rs`). Point `TARISH_MOSEY_LIB` at this `.so` and the daemon
//! runs over `libawdl` + the `wonder` backend instead of Google's library — it does its own
//! mDNS, TLS and transfers on top, unchanged.
//!
//! Only `mosey_start_5` and `mosey_stop` are actually bound by `tarishd`; the rest are
//! harmless stubs for any other caller.
//!
//! The data interface is **`tawdl0`** (not `mosey0` and not Apple's `awdl0`). `tarishd` must
//! be told that name — it reads `persist.tarish.iface` / `$TARISH_IFACE`.

// The wonder backend and AF_PACKET are Linux/Android only; on a dev host this is an empty
// cdylib so the workspace still builds.
#![cfg(any(target_os = "linux", target_os = "android"))]

use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use libawdl_hal::{wonder::Wonder, Radio, TxParams};
use libawdl_session::Config;

/// The wonder monitor the backend drives.
const WONDER_IFACE: &str = "wonder0";

/// The interface the session's data path is carried on — the same name `tarishd` is pointed
/// at (`persist.tarish.iface`). Defaults to `tawdl0`; set the property to `mosey0` to run
/// under a daemon build that still expects the old name.
fn data_iface() -> String {
    if let Ok(v) = std::env::var("TARISH_IFACE") {
        if !v.is_empty() {
            return v;
        }
    }
    read_property("persist.tarish.iface").unwrap_or_else(|| "tawdl0".to_string())
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
    let cc: [u8; 2] = if country.is_null() {
        *b"QA"
    } else {
        let b = unsafe { CStr::from_ptr(country) }.to_bytes();
        [b.first().copied().unwrap_or(b'Q'), b.get(1).copied().unwrap_or(b'A')]
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
    // libmosey's captured bring-up rate; 20 MHz on the 2.4 GHz social channel.
    let params = TxParams { mcs: 3, nss: 2, bandwidth: if channel < 36 { 0 } else { 2 }, short_gi: false };
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
    // Rotate a fresh locally-administered MAC each session, as Apple devices do — a fixed AWDL
    // address reused across many discovery attempts can be negatively cached by iOS.
    cfg.override_mac = Some(random_laa());
    cfg.datapath = Some(iface);
    // duration None: run until mosey_stop.

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut radio = radio;
        log::info!("mosey shim: session starting on ch{channel} cc={}{}", cc[0] as char, cc[1] as char);
        match libawdl_session::run(&mut radio, &cfg, &stop_thread) {
            Ok(s) => log::info!(
                "mosey shim: session ended — {} MIF/{} PSF sent, {} data delivered",
                s.sent_mif, s.sent_psf, s.dp_recvd
            ),
            Err(e) => log::error!("mosey shim: session error: {e:?}"),
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
    log::info!("mosey shim: session stopped");
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
