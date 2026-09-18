//! A backend over Google's `wonder.ko` — the Pixel's AWDL radio shim — driven directly
//! over netlink, with no `libmosey` and no `iw`.
//!
//! # What this is, and why it exists
//!
//! `wonder.ko` is a mac80211 soft-MAC driver that fronts the Pixel's Broadcom firmware and
//! adds the two primitives mainline `nl80211` lacks (a TSF read and a TSF-anchored channel
//! schedule) as OUI-`0x001a11` vendor commands. Google's closed `libmosey` is the only thing
//! that has ever driven it. This module drives it instead — the substance of "replace
//! `libmosey`" at the radio layer.
//!
//! # The bring-up is not invented — it is the captured sequence
//!
//! Every step below was recovered by tracing `libmosey`'s own bring-up on a Pixel 10 Pro
//! (`strace -e trace=network` on `moseyprobe`), decoded byte-for-byte, and recorded in
//! `docs/FINDINGS.md` finding 92. This code reproduces that wire sequence, in that order,
//! because it is the order `wonder.ko` requires:
//!
//! ```text
//!   nl80211  DEL_INTERFACE   wonder0                 (remove the old monitor)
//!   nl80211  NEW_INTERFACE   wonder0 type=monitor    (recreate it)
//!   nl80211  VENDOR SET_REG           country        ┐
//!   nl80211  VENDOR SET_FREQUENCY     freq, bw       │ cached while the HW is stopped;
//!   nl80211  VENDOR SET_FILTER        type, bssid    │ wonder.ko logs each as "caching"
//!   nl80211  VENDOR SET_FIXED_TX_RATE rate           ┘
//!   rtnl     RTM_SETLINK     wonder0 IFF_UP          (the trigger: fires .start(), which
//!                                                     flushes the cache and lights the RF)
//! ```
//!
//! # The non-obvious part
//!
//! The four RF-config vendor commands do nothing when they are sent — `wonder.ko` caches
//! them because the HW is stopped. Nothing takes effect until the monitor interface is
//! brought **UP**, which fires mac80211's `.start()` callback; that is what flushes the
//! cached config and activates the radio. So the order that matters is **configure first,
//! then UP** — the reverse silently brings the radio up with no channel, filter, or rate.
//! This is the same class of "success that isn't" the rest of the HAL is careful about.

#![cfg(any(target_os = "linux", target_os = "android"))]

use crate::caps::Caps;
use crate::{Error, Result, TxParams};

// --- netlink wire constants -------------------------------------------------------------
//
// Native-endian on the wire (netlink is host byte order), which on every target we ship is
// little-endian — matching the capture in finding 92.

const NLMSG_ERROR: u16 = 0x2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;

// nl80211 commands (finding 92 + <linux/nl80211.h>)
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_VENDOR: u8 = 0x67;

// nl80211 attributes
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_VENDOR_ID: u16 = 0xc3;
const NL80211_ATTR_VENDOR_SUBCMD: u16 = 0xc4;
const NL80211_ATTR_VENDOR_DATA: u16 = 0xc5;

const NL80211_IFTYPE_MONITOR: u32 = 6;

/// The OUI `wonder.ko` registers its vendor commands under. Not Broadcom's and not a
/// standard — Google's own, recovered from the module.
const WONDER_OUI: u32 = 0x001a11;

// wonder vendor subcommands, from finding 92's decode.
const WVEN_SET_FREQUENCY: u32 = 0x01;
const WVEN_SET_FILTER: u32 = 0x02;
const WVEN_SET_FIXED_TX_RATE: u32 = 0x03;
const WVEN_SET_REG: u32 = 0x04;
/// Issued last, before the interface is brought up, with an empty payload. It ACKs cleanly
/// and its purpose is not yet identified (it is *not* `GET_MAC`, which is `0x05`). Replicated
/// because `libmosey` sends it; see finding 92.
const WVEN_UNKNOWN_08: u32 = 0x08;

/// The AWDL BSSID. A protocol constant, the same everywhere AWDL appears.
const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

// rtnetlink
const RTM_SETLINK: u16 = 19;
const IFLA_IFNAME: u16 = 3;
const IFF_UP: u32 = 0x1;

// --- netlink message builder ------------------------------------------------------------

/// Builds one netlink message: a 16-byte `nlmsghdr`, then either a 4-byte `genlmsghdr`
/// (generic netlink) or a struct payload, then TLV attributes padded to 4 bytes.
struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    /// A generic-netlink message (`nlmsghdr` + `genlmsghdr`). `family` is the resolved
    /// nl80211 family id, `cmd` the nl80211 command.
    fn genl(family: u16, flags: u16, seq: u32, cmd: u8, version: u8) -> NlMsg {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len, patched in finish()
        buf.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid — kernel fills our port
        buf.push(cmd); // genlmsghdr.cmd
        buf.push(version); // genlmsghdr.version
        buf.extend_from_slice(&0u16.to_ne_bytes()); // reserved
        NlMsg { buf }
    }

    /// An rtnetlink message: `nlmsghdr` then a raw struct payload the caller supplies
    /// (an `ifinfomsg`, here).
    fn rtnl(msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> NlMsg {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(body);
        NlMsg { buf }
    }

    /// Append one attribute. `nla_len` counts the 4-byte header and the data but not the
    /// trailing pad — the pad is added so the next attribute starts 4-byte aligned.
    fn attr(&mut self, atype: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&atype.to_ne_bytes());
        self.buf.extend_from_slice(data);
        let pad = (4 - (len % 4)) % 4;
        self.buf.extend(std::iter::repeat(0u8).take(pad));
    }

    fn attr_u8(&mut self, atype: u16, v: u8) {
        self.attr(atype, &[v]);
    }
    fn attr_u16(&mut self, atype: u16, v: u16) {
        self.attr(atype, &v.to_ne_bytes());
    }
    fn attr_u32(&mut self, atype: u16, v: u32) {
        self.attr(atype, &v.to_ne_bytes());
    }

    /// Patch the length field and take the bytes.
    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Build the `NL80211_ATTR_VENDOR_DATA` blob for a vendor command: a sequence of inner
/// attributes, exactly as they appear inside the container in the capture.
fn vendor_data(build: impl FnOnce(&mut NlMsg)) -> Vec<u8> {
    // Reuse NlMsg's attribute encoder without its header: build into a throwaway genl
    // message and slice off the 8-byte header. Simpler than a second encoder, and the
    // padding rules are identical.
    let mut m = NlMsg::genl(0, 0, 0, 0, 0);
    let header = m.buf.len();
    build(&mut m);
    m.buf[header..].to_vec()
}

// --- the netlink socket -----------------------------------------------------------------

/// A netlink socket (generic or route), with the send-then-read-the-ACK discipline the
/// bring-up needs. Every state-changing message here sets `NLM_F_ACK` and we read the
/// `NLMSG_ERROR` reply, because a vendor command that the driver rejects otherwise fails
/// invisibly — the whole point of this HAL is not to do that.
struct NlSock {
    fd: i32,
    seq: u32,
}

impl NlSock {
    fn open(protocol: i32) -> Result<NlSock> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, protocol) };
        if fd < 0 {
            return Err(Error::Radio(format!(
                "netlink socket: {} — this needs root",
                std::io::Error::last_os_error()
            )));
        }
        // Bind with nl_pid=0 so the kernel assigns our port id; replies are unicast to it.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Radio(format!("netlink bind: {e}")));
        }
        Ok(NlSock { fd, seq: 0 })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Send a fully-built message to the kernel (`nl_pid = 0`).
    fn send(&self, msg: &[u8]) -> Result<()> {
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if n < 0 {
            return Err(Error::Radio(format!(
                "netlink send: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Read one datagram and, if it is an `NLMSG_ERROR`, return its error code (0 = ACK).
    /// Anything that is not an error message is treated as an implicit success for our
    /// purposes — we only issue state changes here, not dumps.
    fn read_ack(&self, what: &str) -> Result<()> {
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n < 0 {
            return Err(Error::Radio(format!(
                "{what}: reading netlink ACK: {}",
                std::io::Error::last_os_error()
            )));
        }
        let n = n as usize;
        if n < 16 {
            return Err(Error::Radio(format!("{what}: truncated netlink reply ({n} bytes)")));
        }
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if msg_type == NLMSG_ERROR {
            // nlmsgerr: the error code is the first 4 bytes after the 16-byte header,
            // as a signed int. 0 means ACK.
            let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if code == 0 {
                return Ok(());
            }
            return Err(Error::Radio(format!(
                "{what}: wonder/kernel rejected it: {} ({})",
                std::io::Error::from_raw_os_error(-code),
                -code
            )));
        }
        Ok(())
    }

    /// Send with an ACK requested and check it.
    fn send_acked(&mut self, mut msg: NlMsg, what: &str) -> Result<()> {
        // Flags live at bytes 6..8; OR in the ACK bit and stamp a fresh seq at 8..12.
        let flags = u16::from_ne_bytes([msg.buf[6], msg.buf[7]]) | NLM_F_REQUEST | NLM_F_ACK;
        msg.buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        let seq = self.next_seq();
        msg.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        let bytes = msg.finish();
        self.send(&bytes)?;
        self.read_ack(what)
    }
}

impl Drop for NlSock {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// --- the radio --------------------------------------------------------------------------

/// The `wonder.ko` backend.
pub struct Wonder {
    /// The monitor interface AWDL rides on — `wonder0` on a Pixel.
    pub monitor: String,
    /// The wiphy index behind it, needed to recreate the monitor.
    wiphy: u32,
    /// Generic-netlink socket for nl80211, opened lazily on first air-touching call.
    genl: Option<NlSock>,
    /// AF_PACKET socket for TX/RX, opened lazily like [`crate::nl80211::Nl80211`].
    sock: Option<crate::rawsock::RawSock>,
}

impl Wonder {
    /// Construct against an existing wonder interface (its wiphy is read now; the index is
    /// not stable across reboots, so it is derived rather than assumed — see
    /// [`crate::nl80211::Nl80211::phy_of`]).
    pub fn new(monitor: &str) -> Result<Wonder> {
        let wiphy = Self::wiphy_of(monitor)?;
        Ok(Wonder { monitor: monitor.to_string(), wiphy, genl: None, sock: None })
    }

    /// Read the wiphy index behind an interface from sysfs.
    ///
    /// **The phy NAME is not the index.** `wonder.ko` names its phy `wonder`, not `phyN`,
    /// so parsing a number out of the name fails ("unparseable phy name"). The numeric
    /// index nl80211 wants lives in `/sys/class/ieee80211/<name>/index` — a separate file —
    /// and there it is `0`. The symlink gives the name; that file gives the index.
    fn wiphy_of(iface: &str) -> Result<u32> {
        let link = std::fs::read_link(format!("/sys/class/net/{iface}/phy80211"))
            .map_err(|e| Error::Radio(format!("no phy for {iface}: {e} — is wonder loaded?")))?;
        let name = link
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::Radio("unreadable phy link".into()))?;
        let idx = std::fs::read_to_string(format!("/sys/class/ieee80211/{name}/index"))
            .map_err(|e| Error::Radio(format!("no index for phy {name}: {e}")))?;
        idx.trim()
            .parse::<u32>()
            .map_err(|_| Error::Radio(format!("unparseable phy index {:?} for {name}", idx.trim())))
    }

    fn ifindex(&self) -> Result<u32> {
        let c = std::ffi::CString::new(self.monitor.as_str())
            .map_err(|_| Error::Radio("bad interface name".into()))?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            return Err(Error::Radio(format!(
                "no interface {}: {}",
                self.monitor,
                std::io::Error::last_os_error()
            )));
        }
        Ok(idx)
    }

    fn genl(&mut self) -> Result<&mut NlSock> {
        if self.genl.is_none() {
            // nl80211 rides generic netlink; the family id is resolved on demand below.
            self.genl = Some(NlSock::open(libc::NETLINK_GENERIC)?);
        }
        Ok(self.genl.as_mut().unwrap())
    }

    /// Resolve the nl80211 generic-netlink family id (`CTRL_CMD_GETFAMILY "nl80211"`).
    ///
    /// Not a constant: it is assigned at load time and differs between kernels (it was
    /// `0x20` in the finding-92 capture, but nothing guarantees that).
    fn nl80211_family(&mut self) -> Result<u16> {
        const GENL_ID_CTRL: u16 = 0x10;
        const CTRL_CMD_GETFAMILY: u8 = 3;
        const CTRL_ATTR_FAMILY_ID: u16 = 1;
        const CTRL_ATTR_FAMILY_NAME: u16 = 2;

        let sock = self.genl()?;
        let seq = sock.next_seq();
        let mut m = NlMsg::genl(GENL_ID_CTRL, NLM_F_REQUEST, seq, CTRL_CMD_GETFAMILY, 1);
        m.attr(CTRL_ATTR_FAMILY_NAME, b"nl80211\0");
        sock.send(&m.finish())?;

        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::recv(sock.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n < 20 {
            return Err(Error::Radio("resolving nl80211 family: short reply".into()));
        }
        let n = n as usize;
        // Walk the attributes after nlmsghdr(16) + genlmsghdr(4) for CTRL_ATTR_FAMILY_ID.
        let mut off = 20;
        while off + 4 <= n {
            let alen = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
            let atype = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
            if alen < 4 || off + alen > n {
                break;
            }
            if atype == CTRL_ATTR_FAMILY_ID && alen >= 6 {
                return Ok(u16::from_ne_bytes([buf[off + 4], buf[off + 5]]));
            }
            off += (alen + 3) & !3; // NLA_ALIGN
        }
        Err(Error::Radio("nl80211 family id not in reply — is the driver loaded?".into()))
    }

    /// One vendor command: `NL80211_CMD_VENDOR` with our OUI, the subcommand, and its data
    /// blob, targeted at the monitor interface. This is the shape every RF-config step takes.
    fn vendor(&mut self, family: u16, ifindex: u32, subcmd: u32, data: &[u8], what: &str) -> Result<()> {
        let sock = self.genl.as_mut().unwrap();
        let mut m = NlMsg::genl(family, NLM_F_REQUEST, 0, NL80211_CMD_VENDOR, 1);
        m.attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        m.attr_u32(NL80211_ATTR_VENDOR_ID, WONDER_OUI);
        m.attr_u32(NL80211_ATTR_VENDOR_SUBCMD, subcmd);
        m.attr(NL80211_ATTR_VENDOR_DATA, data);
        sock.send_acked(m, what)
    }

    /// Bring `wonder.ko`'s radio up on `channel` with `params`, reproducing `libmosey`'s
    /// captured sequence (finding 92). After this returns, [`Wonder`] can transmit through
    /// the monitor. `country` is applied first, as `libmosey` does.
    ///
    /// Order is load-bearing: configure (the driver caches it), then UP (the driver applies
    /// it). See the module note.
    pub fn bring_up(&mut self, channel: u8, params: TxParams, country: [u8; 2]) -> Result<()> {
        let family = self.nl80211_family()?;
        let wiphy = self.wiphy;

        // 1. DEL + NEW: recreate wonder0 as a fresh monitor.
        {
            let old_idx = self.ifindex().ok();
            let sock = self.genl.as_mut().unwrap();
            if let Some(idx) = old_idx {
                let mut m = NlMsg::genl(family, NLM_F_REQUEST, 0, NL80211_CMD_DEL_INTERFACE, 1);
                m.attr_u32(NL80211_ATTR_IFINDEX, idx);
                sock.send_acked(m, "DEL_INTERFACE wonder0")?;
            }
            let mut m = NlMsg::genl(family, NLM_F_REQUEST, 0, NL80211_CMD_NEW_INTERFACE, 1);
            m.attr_u32(NL80211_ATTR_WIPHY, wiphy);
            m.attr_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
            let mut name = self.monitor.clone().into_bytes();
            name.push(0); // nl80211 wants the interface name NUL-terminated
            m.attr(NL80211_ATTR_IFNAME, &name);
            sock.send_acked(m, "NEW_INTERFACE wonder0 monitor")?;
        }

        // The recreated interface has a new index — look it up now, target the rest at it.
        let ifindex = self.ifindex()?;

        // 2. The four RF-config vendor commands. wonder.ko caches each (HW still stopped).
        //    SET_REG: one string attr, country + NUL, exactly as captured.
        let reg = vendor_data(|m| {
            let mut cc = country.to_vec();
            cc.push(0);
            m.attr(1, &cc);
        });
        self.vendor(family, ifindex, WVEN_SET_REG, &reg, "SET_REG")?;

        //    SET_FREQUENCY: freq in MHz (u32), bandwidth (u16: 0=20,1=40,2=80).
        let freq = channel_to_mhz(channel)?;
        let bw = params.bandwidth as u16;
        let sf = vendor_data(|m| {
            m.attr_u32(1, freq);
            m.attr_u16(2, bw);
        });
        self.vendor(family, ifindex, WVEN_SET_FREQUENCY, &sf, "SET_FREQUENCY")?;

        //    SET_FILTER: filter type (u32) + nested { enabled (u8), bssid (6) }. The nested
        //    attribute carries no NLA_F_NESTED flag in the capture, so we don't set one.
        let filt = vendor_data(|m| {
            m.attr_u32(1, 0); // filter type 0, as libmosey sends
            let nested = vendor_data(|n| {
                n.attr_u8(1, 1); // BSSID filter enabled
                n.attr(2, &AWDL_BSSID);
            });
            m.attr(2, &nested);
        });
        self.vendor(family, ifindex, WVEN_SET_FILTER, &filt, "SET_FILTER")?;

        //    SET_FIXED_TX_RATE: preamble(u32), bw(u16), gi(u32), nss(u8), mcs(u8). Bring-up
        //    replicates libmosey's captured VHT rate (Pre=2, Bw=2, Gi=2, Nss=2, Mcs=3);
        //    per-frame rate for action frames is a separate, lower setting (see TxParams).
        let rate = vendor_data(|m| {
            m.attr_u32(1, 2); // preamble = VHT
            m.attr_u16(2, params.bandwidth as u16);
            m.attr_u32(3, if params.short_gi { 1 } else { 2 }); // gi (libmosey: 2)
            m.attr_u8(4, params.nss);
            m.attr_u8(5, params.mcs);
        });
        self.vendor(family, ifindex, WVEN_SET_FIXED_TX_RATE, &rate, "SET_FIXED_TX_RATE")?;

        //    subcmd 0x08, empty — libmosey issues it here; purpose unidentified (finding 92).
        self.vendor(family, ifindex, WVEN_UNKNOWN_08, &[], "vendor subcmd 0x08")?;

        // 3. The trigger: bring wonder0 UP over rtnetlink. This fires mac80211 .start(),
        //    which flushes everything cached above and lights the RF. Nothing before this
        //    line has taken effect.
        self.set_link_up(ifindex)?;
        Ok(())
    }

    /// `RTM_SETLINK` with `IFF_UP` — the single rtnetlink message that activates the radio.
    fn set_link_up(&self, ifindex: u32) -> Result<()> {
        let mut rt = NlSock::open(libc::NETLINK_ROUTE)?;
        // ifinfomsg: family(u8) pad(u8) type(u16) index(i32) flags(u32) change(u32).
        let mut body = Vec::with_capacity(16);
        body.push(0u8); // AF_UNSPEC
        body.push(0u8); // pad
        body.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
        body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
        body.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_flags
        body.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change — only the UP bit
        let mut m = NlMsg::rtnl(RTM_SETLINK, NLM_F_REQUEST, 0, &body);
        // Name it too, harmless with a valid index and what libmosey sends.
        let mut name = self.monitor.clone().into_bytes();
        name.push(0);
        m.attr(IFLA_IFNAME, &name);
        rt.send_acked(m, "RTM_SETLINK wonder0 up")
    }
}

/// 802.11 channel number → centre frequency in MHz. Covers the 2.4 and 5 GHz plans AWDL
/// uses; the 5 GHz social channels (44, 149) are the ones that matter here.
fn channel_to_mhz(ch: u8) -> Result<u32> {
    match ch {
        1..=13 => Ok(2407 + ch as u32 * 5),
        14 => Ok(2484),
        36..=177 => Ok(5000 + ch as u32 * 5),
        _ => Err(Error::Radio(format!("channel {ch} is not a frequency we map"))),
    }
}

impl crate::Radio for Wonder {
    fn capabilities(&self) -> Result<Caps> {
        // wonder exposes the two AWDL primitives as vendor commands, but finding 88
        // established that get_mac_tsf / set_channel_schedule_req are STUBS on the shipping
        // module — the timing is done in libmosey's software, not the hardware. So this
        // backend is honestly SoftTimed, not HwTimed, and we do not claim a TSF read.
        Ok(Caps {
            tx_channels: vec![44, 149],
            active_monitor: true,
            injection: true,
            tsf: None,
            scheduled_channels: false,
            channel_switch_us: None,
            fixed_tx_rate: true,
            rx_filter_offload: true, // SET_FILTER exists and works (finding 92)
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
        let family = self.nl80211_family()?;
        let ifindex = self.ifindex()?;
        let reg = vendor_data(|m| {
            let mut cc = country.to_vec();
            cc.push(0);
            m.attr(1, &cc);
        });
        self.vendor(family, ifindex, WVEN_SET_REG, &reg, "SET_REG")
    }

    fn set_channel(&mut self, channel: u8) -> Result<()> {
        let family = self.nl80211_family()?;
        let ifindex = self.ifindex()?;
        let freq = channel_to_mhz(channel)?;
        let sf = vendor_data(|m| {
            m.attr_u32(1, freq);
            m.attr_u16(2, 2); // 80 MHz, as libmosey uses on the social channels
        });
        self.vendor(family, ifindex, WVEN_SET_FREQUENCY, &sf, "SET_FREQUENCY")
    }

    fn tsf(&self) -> Result<crate::Tsf> {
        // get_mac_tsf is a stub on the shipping wonder.ko (finding 88): it does not return a
        // real hardware TSF. Faking one from the host clock is exactly the lie the trait
        // forbids, so this is Unsupported and the layer above uses radiotap TSFT / software
        // timing — which is what libmosey itself does.
        Err(Error::Unsupported(
            "wonder.ko get_mac_tsf is a stub (finding 88); no real hardware TSF read",
        ))
    }

    fn set_channel_schedule(&mut self, _slots: &[crate::Slot], _anchor: crate::Tsf) -> Result<()> {
        Err(Error::Unsupported(
            "wonder.ko set_channel_schedule_req is a stub (finding 88); schedule in software",
        ))
    }

    fn tx(&mut self, frame: &[u8], _params: TxParams) -> Result<()> {
        if self.sock.is_none() {
            self.sock = Some(crate::rawsock::RawSock::open(&self.monitor)?);
        }
        self.sock.as_ref().unwrap().tx(frame)
    }

    fn rx(&mut self, timeout_ms: u32) -> Result<Option<crate::RxFrame>> {
        if self.sock.is_none() {
            let s = crate::rawsock::RawSock::open(&self.monitor)?;
            let _ = s.enable_timestamps();
            self.sock = Some(s);
        }
        let sock = self.sock.as_ref().unwrap();
        let mut buf = vec![0u8; 4096];
        let got = if timeout_ms == 0 {
            sock.rx_now(&mut buf)?
        } else {
            sock.set_rx_timeout(timeout_ms)?;
            sock.rx_at(&mut buf)?
        };
        let Some((n, host_us)) = got else { return Ok(None) };
        buf.truncate(n);
        // wonder.ko delivers radiotap-prefixed frames on the monitor like any mac80211
        // driver, so the same parser as nl80211.rs applies. Whether TSFT is actually present
        // is a question a capture answers — the parser reports it honestly as None when absent.
        let (tsf, freq, signal) = crate::nl80211::libawdl_radiotap(&buf).unwrap_or((None, None, None));
        Ok(Some(crate::RxFrame { bytes: buf, host_us, tsf, freq_mhz: freq, signal_dbm: signal }))
    }
}
