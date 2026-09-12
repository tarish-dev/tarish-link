//! A backend over mainline Linux: `nl80211` for control, monitor mode for traffic.
//!
//! **This is the reference implementation of [`crate::Radio`] and the proof the seam is
//! real.** It runs on any adapter with monitor mode and injection — an ALFA
//! AWUS036ACM on `mt76` is what it was written against — with no vendor code of any
//! kind. A manufacturer can compare their backend against this one on the same
//! captures.
//!
//! It reaches [`Tier::SoftTimed`] and cannot reach [`Tier::HwTimed`], because mainline
//! `nl80211` exposes neither a TSF read nor a TSF-anchored channel schedule. That is
//! not a defect here; it is the finding. Those two primitives are exactly what Google
//! added to `wonder.ko`, and this backend is what makes their absence measurable rather
//! than theoretical.
//!
//! ## The trap this backend encodes
//!
//! The managed interface on the same phy **must be down** before the monitor vif can
//! transmit or change channel. Leave it up and `mt76` fails as a success: every
//! injection returns `EAGAIN`, channel changes report `Device or resource busy`, and
//! `dmesg` says nothing. The adapter is fine — `aireplay-ng -9` gets 30/30 on the same
//! radio at the same moment. [`Nl80211::bring_up`] does it in the right order.

use std::process::Command;

use crate::caps::Caps;
use crate::{Error, Result};

/// Control-plane calls go through `iw`.
///
/// A netlink implementation belongs here eventually and would remove the dependency on
/// a binary being installed. It is deliberately not the first thing built: `iw` is
/// exact, it is what every capability we care about is documented in terms of, and
/// getting the seam right matters more than getting it fast. Channel switching through
/// a process spawn is far too slow for per-slot hopping, which is one more reason
/// [`Tier::SoftTimed`] is an honest ceiling here.
/// Where `iw` actually lives.
///
/// NOT just "iw". It is a network-administration tool and ships in `/usr/sbin`, which is
/// absent from a non-login shell's PATH on Debian — so invoking it by bare name works
/// from an interactive session and fails from a service, a cron job, or a program started
/// any other way. Found by running this probe on a Pi, where it reported
/// `running iw: No such file or directory` from a shell in which `iw` plainly worked.
fn ip_path() -> &'static str {
    for p in ["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    "ip"
}

fn iw_path() -> &'static str {
    for p in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "/bin/iw"] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    // Let PATH have the last word rather than failing here: a system that puts it
    // somewhere unusual should still work if PATH knows.
    "iw"
}

fn iw(args: &[&str]) -> Result<String> {
    let out = Command::new(iw_path())
        .args(args)
        .output()
        .map_err(|e| Error::Radio(format!("running {}: {e}", iw_path())))?;
    if !out.status.success() {
        return Err(Error::Radio(String::from_utf8_lossy(&out.stderr).trim().to_string()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub struct Nl80211 {
    /// The monitor interface AWDL rides on, e.g. `mon0`.
    pub monitor: String,
    /// The managed interface on the same phy, which must be held down.
    pub managed: String,
    pub phy: String,
}

impl Nl80211 {
    /// Locate the phy behind an interface.
    ///
    /// Derived rather than configured, because **the phy index is not stable**: an
    /// adapter observed as `phy2` came back as `phy1` after a reboot, and a hardcoded
    /// index fails with `No such device (-19)` — which reads like the adapter is
    /// missing rather than renumbered.
    pub fn phy_of(iface: &str) -> Result<String> {
        let link = std::fs::read_link(format!("/sys/class/net/{iface}/phy80211"))
            .map_err(|e| Error::Radio(format!("no phy for {iface}: {e}")))?;
        link.file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or(Error::Radio("unreadable phy link".into()))
    }

    pub fn new(managed: &str, monitor: &str) -> Result<Nl80211> {
        Ok(Nl80211 {
            phy: Self::phy_of(managed)?,
            managed: managed.to_string(),
            monitor: monitor.to_string(),
        })
    }

    /// Create the monitor vif and put the radio in a state where it will actually
    /// transmit. Order matters; see the module note.
    pub fn bring_up(&self, channel: u8) -> Result<()> {
        // Down first. This is the whole trick.
        // `ip` is in /sbin for the same reason `iw` is in /usr/sbin.
        let _ = Command::new(ip_path()).args(["link", "set", &self.managed, "down"]).status();
        let _ = iw(&["dev", &self.monitor, "del"]);
        iw(&["phy", &self.phy, "interface", "add", &self.monitor, "type", "monitor"])?;
        Command::new(ip_path())
            .args(["link", "set", &self.monitor, "up"])
            .status()
            .map_err(|e| Error::Radio(format!("bringing up {}: {e}", self.monitor)))?;
        iw(&["dev", &self.monitor, "set", "channel", &channel.to_string()])?;
        Ok(())
    }
}

impl crate::Radio for Nl80211 {
    fn capabilities(&self) -> Result<Caps> {
        let info = iw(&["phy", &self.phy, "info"])?;

        // TRANSMIT, not merely present. A channel line carries "(no IR)" when the
        // regulatory domain forbids initiating radiation on it, and a radio in
        // `country 00` lists 44 and 149 exactly that way — present, and useless.
        // "(radar detection)" marks DFS, which is a constraint but not a refusal:
        // measured on this hardware, injection on 149 under DFS succeeds.
        let mut tx_channels = Vec::new();
        for line in info.lines() {
            let l = line.trim();
            if !l.starts_with('*') || !l.contains("MHz [") {
                continue;
            }
            if l.contains("no IR") || l.contains("disabled") {
                continue;
            }
            if let Some(open) = l.find('[') {
                if let Some(close) = l[open..].find(']') {
                    if let Ok(ch) = l[open + 1..open + close].parse::<u8>() {
                        tx_channels.push(ch);
                    }
                }
            }
        }

        Ok(Caps {
            tx_channels,
            active_monitor: info.contains("Device supports active monitor"),
            // If the phy offers a monitor mode at all, mac80211 will accept injection
            // on it. Whether frames leave the antenna is a separate question and is
            // not answerable by reading capabilities -- see `probe_injection`.
            injection: info.contains("* monitor"),
            // Mainline nl80211 has no TSF read. This is the gap, stated plainly.
            tsf: None,
            scheduled_channels: false,
            channel_switch_us: None,
            fixed_tx_rate: info.contains("set_fixed_tx_rate"),
            rx_filter_offload: false,
        })
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", self.monitor))
            .map_err(|e| Error::Radio(format!("reading MAC: {e}")))?;
        let mut mac = [0u8; 6];
        for (i, part) in s.trim().split(':').enumerate() {
            if i >= 6 {
                break;
            }
            mac[i] = u8::from_str_radix(part, 16).map_err(|_| Error::Radio("bad MAC".into()))?;
        }
        Ok(mac)
    }

    fn set_regulatory(&mut self, country: [u8; 2]) -> Result<()> {
        let c = std::str::from_utf8(&country).map_err(|_| Error::Radio("bad country".into()))?;
        iw(&["reg", "set", c]).map(|_| ())
    }

    fn set_channel(&mut self, channel: u8) -> Result<()> {
        match iw(&["dev", &self.monitor, "set", "channel", &channel.to_string()]) {
            Ok(_) => Ok(()),
            // "Device or resource busy" here almost always means the managed interface
            // is up on this phy, not that anything is genuinely busy.
            Err(Error::Radio(m)) if m.contains("busy") => Err(Error::Radio(format!(
                "{m} — is {} still up? the managed interface must be down",
                self.managed
            ))),
            Err(e) => Err(e),
        }
    }

    fn tsf(&self) -> Result<crate::Tsf> {
        // Deliberately not faked from the host clock. The peer is synchronised to the
        // MAC's counter, and substituting CLOCK_MONOTONIC produces a number that looks
        // plausible, drifts, and fails only once a cluster will not hold.
        Err(Error::Unsupported(
            "mainline nl80211 exposes no MAC TSF read; radiotap TSFT on received frames \
             is the only available anchor",
        ))
    }

    fn set_channel_schedule(&mut self, _slots: &[crate::Slot], _anchor: crate::Tsf) -> Result<()> {
        Err(Error::Unsupported(
            "mainline nl80211 has no TSF-anchored channel schedule; drive set_channel \
             on a timer and accept host scheduler jitter",
        ))
    }

    fn tx(&mut self, _frame: &[u8], _params: TxParamsAlias) -> Result<()> {
        // Injection is a data-plane operation and belongs on a raw socket bound to the
        // monitor interface, not on a process spawn. It is wired up in the capture
        // tool, which already owns a pcap handle; duplicating that here would mean two
        // handles on one interface.
        Err(Error::Unsupported("tx is not wired to this backend yet — see the CLI crate"))
    }

    fn rx(&mut self, _timeout_ms: u32) -> Result<Option<crate::RxFrame>> {
        Err(Error::Unsupported("rx is not wired to this backend yet — see the CLI crate"))
    }
}

use crate::TxParams as TxParamsAlias;
