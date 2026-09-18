//! Minimal AWDL frame injector.
//!
//! Builds frames with `libawdl` and transmits them through `libawdl-hal`'s AF_PACKET path.
//! No `pcap`, no phy management — which is the point: it links only the two crates that
//! cross-compile for Android, so it is the thin portable entry point for the phone track
//! (decision B / finding 88). Its job is to answer one question on whatever radio it is
//! pointed at: **does injection through this monitor interface actually reach the air?**
//!
//! Interface setup — monitor mode, channel, and (on the phone) an active `wonder` session —
//! is the caller's job with `iw`/`ip`/`moseyprobe`. This only opens the interface and sends.

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    let mut args: Vec<String> = std::env::args().collect();

    // `wonder-up` as the first token means: bring the wonder radio up ourselves — no
    // libmosey, no moseyprobe — using the captured bring-up sequence (findings 91–92),
    // then inject. This is the standalone-backend test. Without it we behave as before and
    // assume the caller (iw/moseyprobe) already brought the interface up.
    let bring_up_wonder = args.get(1).map(|s| s == "wonder-up").unwrap_or(false);
    if bring_up_wonder {
        args.remove(1);
    }

    if args.len() < 3 {
        eprintln!("usage: awdl-inject [wonder-up] <iface> <channel> [count] [psf-per-mif]");
        eprintln!("  <iface> must be an UP monitor interface (mon0 on a Pi; a wonder monitor");
        eprintln!("  during a live session on a Pixel). count defaults 100, psf-per-mif 2.");
        eprintln!("  wonder-up: on a Pixel, bring wonder's RF up ourselves before injecting.");
        std::process::exit(2);
    }
    let iface = &args[1];
    let channel: u8 = args[2].parse().expect("channel must be a number");
    let count: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
    let psf_per_mif: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(2);

    if bring_up_wonder {
        // libmosey's captured bring-up rate: VHT, 80 MHz, 2 streams, MCS 3 (finding 92).
        let params = libawdl_hal::TxParams { mcs: 3, nss: 2, bandwidth: 2, short_gi: false };
        let mut w = match libawdl_hal::wonder::Wonder::new(iface) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("wonder init on {iface}: {e:?}");
                std::process::exit(1);
            }
        };
        match w.bring_up(channel, params, *b"QA") {
            Ok(()) => eprintln!("wonder-up: RF up on {iface} ch{channel} (standalone, no libmosey)"),
            Err(e) => {
                eprintln!("wonder-up: bring-up failed: {e:?}");
                std::process::exit(1);
            }
        }
    }

    // Our AWDL address is the interface's own MAC when we can read it, else a stable
    // locally-administered default. Peers derive our IPv6 from whatever we advertise, so a
    // real interface MAC keeps the frame self-consistent.
    let addr = mac_of(iface).unwrap_or([0x00, 0xc0, 0xca, 0x11, 0x22, 0x33]);
    eprintln!("awdl-inject: {iface} ch{channel} as {addr:02x?}, {count} frames, 1 MIF per {psf_per_mif} PSF");

    let mut b = libawdl::beacon::Beacon::new(addr, channel, "QA");
    b.metric = libawdl::beacon::METRIC_COMPETE;

    let sock = match libawdl_hal::rawsock::RawSock::open(iface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open {iface}: {e:?}");
            std::process::exit(1);
        }
    };

    let epoch = std::time::Instant::now();
    let (mut sent, mut failed) = (0u32, 0u32);
    let mut first_err: Option<String> = None;
    for n in 0..count {
        let now_us = epoch.elapsed().as_micros() as u64;
        let is_mif = psf_per_mif == 0 || n % (psf_per_mif + 1) == 0;
        let frame = if is_mif { b.mif(now_us) } else { b.psf(now_us) };
        match sock.tx(&frame) {
            Ok(()) => sent += 1,
            Err(e) => {
                failed += 1;
                if first_err.is_none() {
                    first_err = Some(format!("{e:?}"));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    eprintln!("sent {sent}, failed {failed}");
    if let Some(e) = first_err {
        eprintln!("first error: {e}");
    }
    if sent == 0 {
        std::process::exit(1);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mac_of(iface: &str) -> Option<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
    let mut m = [0u8; 6];
    let mut n = 0;
    for part in s.trim().split(':') {
        if n >= 6 {
            return None;
        }
        m[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n == 6 { Some(m) } else { None }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    eprintln!("awdl-inject needs Linux or Android (AF_PACKET injection)");
    std::process::exit(1);
}
