//! Ask a radio what it can do, and say which AWDL tier that buys.
//!
//! This is the vendor-facing output of the HAL: run it against a chip and it either
//! reports `HwTimed`, or lists exactly which primitives are missing. Run it as:
//!
//! ```sh
//! cargo run --release --example probe -- wlan0 mon0
//! ```

use libawdl_hal::{nl80211::Nl80211, Radio, SOCIAL_CHANNELS};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: probe <managed-iface> <monitor-iface>");
        std::process::exit(2);
    }

    let radio = match Nl80211::new(&args[1], &args[2]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot address that radio: {e:?}");
            std::process::exit(1);
        }
    };
    println!("phy            {}", radio.phy);

    match radio.mac_address() {
        Ok(m) => println!(
            "address        {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ),
        Err(e) => println!("address        unavailable: {e:?}"),
    }

    let caps = match radio.capabilities() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("capability probe failed: {e:?}");
            std::process::exit(1);
        }
    };

    let social: Vec<u8> =
        SOCIAL_CHANNELS.iter().copied().filter(|c| caps.tx_channels.contains(c)).collect();

    println!("\nTRANSMIT-capable AWDL social channels: {social:?}");
    println!("  (presence is not permission — a channel flagged no-IR is excluded here)");
    println!("\nactive monitor (ACKs rx)  {}", yn(caps.active_monitor));
    println!("injection                 {}", yn(caps.injection));
    println!("MAC TSF readable          {}", match caps.tsf {
        Some(p) => format!("yes, {} us", p.0),
        None => "NO".into(),
    });
    println!("TSF channel schedule      {}", yn(caps.scheduled_channels));
    println!("fixed TX rate             {}", yn(caps.fixed_tx_rate));
    println!("rx filter offload         {}", yn(caps.rx_filter_offload));

    println!("\n==> tier: {:?}", caps.tier());
    let gaps = caps.gaps_to_hw_timed();
    if gaps.is_empty() {
        println!("    nothing missing for hardware-timed AWDL");
    } else {
        println!("    to reach HwTimed, this radio still needs:");
        for g in gaps {
            println!("      - {g}");
        }
    }
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "NO"
    }
}
