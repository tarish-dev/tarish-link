//! The `awdl0` netdev — where IP meets the radio.
//!
//! Without this, libawdl is a control-plane library: it can join a cluster, hold a
//! schedule and be elected master, and cannot carry a single byte. An AWDL implementation
//! needs an ordinary network interface so that a socket can bind to it and the kernel's
//! own IPv6 stack does the work it is already good at.
//!
//! ## Why a TUN and not a TAP
//!
//! TAP hands you Ethernet frames, which sounds closer to 802.11 and is not: the frame we
//! have to build is QoS Data with an AWDL-specific SNAP and a data header in between
//! (`libawdl::data`), so an Ethernet header would be discarded immediately. TUN hands you
//! the IP packet, which is exactly the payload that goes inside. **All 428 measured AWDL
//! data frames carry IPv6 and none carry IPv4**, so the interface is an IPv6 one in
//! practice.
//!
//! ## Two things the caller still has to do, which no amount of opening a device fixes
//!
//! **The address is derived, not assigned.** A peer's address is the modified EUI-64 of
//! its AWDL MAC — see [`libawdl::data::link_local_from_mac`] — so this interface must
//! carry the link-local of *our* AWDL address or peers will compute one we are not
//! listening on.
//!
//! **The kernel will add its own link-local, and it will be the wrong one.** Measured on the
//! Pi: bring `awdl0` up and it acquires a *second* address,
//! `fe80::66b6:3871:d3dc:2e0d scope link stable-privacy`, beside the derived one. Peers
//! compute the EUI-64 address and send to it, while the kernel may choose the
//! stable-privacy address as the *source* for our replies — so traffic arrives and
//! answers come from an address the peer has never heard of.
//!
//! `addr_gen_mode` reads back as `0`, meaning EUI-64, which looks correct and is not: a
//! TUN has no hardware address at all (`ip link` shows `link/none`), so EUI-64 has nothing
//! to derive from and the kernel falls back to stable-privacy. Set the mode to **1**
//! (none) and do it **before** the interface comes up, because it is only consulted at
//! that point:
//!
//! ```text
//!   sysctl -w net.ipv6.conf.awdl0.addr_gen_mode=1
//!   ip link set awdl0 up
//!   ip -6 addr add <derived>/64 dev awdl0 scope link
//! ```
//!
//! With that, `ip -6 addr show awdl0` lists exactly one address. Verified.
//!
//! **A route without an `ip rule` is never consulted.** Android routes by fwmark and the
//! per-network table starts empty; the failure looks exactly like nothing listening on the
//! port, which is the single most expensive false diagnosis in this project's history.
//! On Linux the equivalent trap is a link-local route that needs the interface named:
//!
//! ```text
//!   ip -6 route add fe80::/64 dev awdl0 table <id>
//!   ip -6 rule add iif awdl0 table <id>
//! ```
//!
//! This module deliberately does not run those. It opens the device and gets out of the
//! way, because a HAL that quietly reconfigures routing is a HAL you cannot debug.

use crate::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const IFF_TUN: libc::c_short = 0x0001;
/// No packet-information prefix. Without this every read is preceded by four bytes of
/// flags and protocol, and the IPv6 version nibble lands in the wrong place — which
/// presents as "the peer sent us garbage" rather than as a configuration mistake.
const IFF_NO_PI: libc::c_short = 0x1000;

/// `TUNSETIFF`. `_IOW('T', 202, int)`, and it is 32-bit on every Linux architecture.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    flags: libc::c_short,
    // The real `ifreq` is a union large enough for a sockaddr; only the flags are read for
    // TUNSETIFF, but the kernel copies the whole thing, so it has to be the full size.
    pad: [u8; 22],
}

pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    /// Create or attach to a TUN interface.
    ///
    /// The interface comes up **down and without an address**; bringing it up and giving
    /// it the derived link-local is the caller's job, for the reason in the module note.
    pub fn open(name: &str) -> Result<Tun> {
        if name.len() >= libc::IF_NAMESIZE {
            return Err(Error::Radio(format!(
                "interface name {name:?} is {} bytes; the kernel allows {}",
                name.len(),
                libc::IF_NAMESIZE - 1
            )));
        }

        // SAFETY: a constant path, and the result is checked before use.
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Radio(format!(
                "open /dev/net/tun: {e}. Needs CAP_NET_ADMIN, and the tun module loaded \
                 (modprobe tun)"
            )));
        }
        // SAFETY: `raw` is a fresh, valid, owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut req = IfReq {
            name: [0; libc::IF_NAMESIZE],
            flags: IFF_TUN | IFF_NO_PI,
            pad: [0; 22],
        };
        for (dst, b) in req.name.iter_mut().zip(name.as_bytes()) {
            *dst = *b as libc::c_char;
        }

        // SAFETY: `req` is correctly shaped for TUNSETIFF and outlives the call.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Radio(format!(
                "TUNSETIFF {name}: {e}. EPERM means no CAP_NET_ADMIN; EBUSY means the name \
                 is taken by an interface of a different type"
            )));
        }

        Ok(Tun { fd, name: name.to_string() })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// One IP packet from the kernel, to be encapsulated and injected.
    ///
    /// A TUN read returns exactly one packet, so a short buffer **truncates and loses the
    /// rest** rather than returning it next time. 1500 is not enough for AWDL, whose MTU
    /// the peer chooses; give it at least 2048.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // SAFETY: writing at most `buf.len()` into `buf`.
        let n = unsafe {
            libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n < 0 {
            return Err(Error::Radio(format!("read {}: {}", self.name, std::io::Error::last_os_error())));
        }
        if n as usize == buf.len() {
            return Err(Error::Radio(format!(
                "read {} filled the whole {}-byte buffer, so the packet was probably \
                 truncated; a TUN read returns one packet and loses the remainder",
                self.name,
                buf.len()
            )));
        }
        Ok(n as usize)
    }

    /// Hand a decapsulated IP packet to the kernel, as if it had arrived on a wire.
    pub fn write(&self, pkt: &[u8]) -> Result<usize> {
        // SAFETY: reading exactly `pkt.len()` from `pkt`.
        let n = unsafe {
            libc::write(self.fd.as_raw_fd(), pkt.as_ptr() as *const libc::c_void, pkt.len())
        };
        if n < 0 {
            return Err(Error::Radio(format!("write {}: {}", self.name, std::io::Error::last_os_error())));
        }
        Ok(n as usize)
    }

    /// Block for at most this long on the next [`Tun::read`].
    ///
    /// The data plane has to interleave reading the tun with reading the radio, and a
    /// blocking read on either starves the other. A timeout is the smallest thing that
    /// works; `poll` on both descriptors is the right answer when one loop runs both.
    pub fn set_read_timeout(&self, ms: u32) -> Result<()> {
        let tv = libc::timeval {
            tv_sec: libc::time_t::from(ms / 1000),
            tv_usec: libc::suseconds_t::from((ms % 1000) * 1000),
        };
        // SAFETY: a correctly-sized timeval for SO_RCVTIMEO.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            // A TUN fd is a character device, not a socket, so this is expected to fail on
            // some kernels. Reported rather than swallowed: the caller needs to know it
            // has to poll instead of relying on a timeout that was never set.
            return Err(Error::Unsupported(
                "SO_RCVTIMEO on a TUN descriptor; poll() the fd instead",
            ));
        }
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}
