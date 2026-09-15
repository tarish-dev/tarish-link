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
//! **Routing is NOT a problem here, and an earlier version of this note said it was.**
//! Android routes by fwmark with an empty per-network table, so a route without an
//! `ip rule` is never consulted — the single most expensive false diagnosis in this
//! project's history. That is an Android problem. On Linux the kernel installs
//! `fe80::/64 proto kernel metric 256` on its own the moment the address is added, and
//! `ip -6 route show dev awdl0` confirms it. No table, no rule, nothing to add.
//!
//! The Android trap is still real and still worth carrying forward to a phone port. It
//! just does not apply to the machine this runs on, and saying otherwise sends someone
//! looking for a fault that is not there.

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
        // `as`, not `From`: time_t and suseconds_t are i64 on 64-bit and i32 on 32-bit
        // (armv7, the Pi 400), so `i32::from(u32)` does not compile there. The values are a
        // second count and a microsecond count derived from a u32 of milliseconds, both far
        // inside i32 range, so the cast is lossless in practice.
        let tv = libc::timeval {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
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

/// `SIOCGIFFLAGS` / `SIOCSIFFLAGS` / `SIOCSIFADDR`.
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCSIFADDR: libc::c_ulong = 0x8916;

/// `struct in6_ifreq` — the AF_INET6 form, which is a different shape from `ifreq` and is
/// not interchangeable with it.
#[repr(C)]
struct In6IfReq {
    addr: [u8; 16],
    prefixlen: u32,
    ifindex: i32,
}

impl Tun {
    /// Bring the interface up and give it the address peers will compute for us.
    ///
    /// **The order is the whole content of this function** and it is not the order anyone
    /// writes by hand:
    ///
    /// 1. `addr_gen_mode = 1`, **before** the interface comes up. It is read once, at that
    ///    moment. Skip it and the kernel adds a stable-privacy link-local of its own
    ///    beside ours and may use *that* as the source address — so peers reach us at the
    ///    derived address and our replies come from one they have never heard of.
    ///    Discovery works and every answer is dropped. Finding 51.
    /// 2. `IFF_UP`.
    /// 3. the derived address.
    ///
    /// Doing 3 before 2 also works; doing 1 after 2 does not, and fails silently, which is
    /// why this exists as one function rather than three the caller sequences.
    ///
    /// The address is **not** a parameter. It is derived from the MAC we advertise, because
    /// any other value is wrong by construction — AWDL peers compute it, they are never
    /// told it.
    pub fn configure(&self, mac: [u8; 6]) -> Result<std::net::Ipv6Addr> {
        let raw = crate::tun::addr_gen_mode_path(&self.name);
        // Written before IFF_UP. std::fs rather than an ioctl because this is a sysctl and
        // there is no ioctl for it.
        std::fs::write(&raw, "1\n").map_err(|e| {
            Error::Radio(format!(
                "write {raw}: {e}. Without addr_gen_mode=1 the kernel adds its own \
                 link-local and may prefer it as the source address"
            ))
        })?;

        // SAFETY: a socket used only as an ioctl handle; closed below.
        let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(Error::Radio(format!(
                "AF_INET6 socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let close = |s: i32| {
            // SAFETY: `s` is the descriptor opened above and is not used afterwards.
            unsafe { libc::close(s) };
        };

        // IFF_UP, read-modify-write. Setting the flags word wholesale would clear
        // MULTICAST, which a link carrying mDNS to ff02::fb cannot do without.
        let mut req = IfReq { name: [0; libc::IF_NAMESIZE], flags: 0, pad: [0; 22] };
        for (dst, b) in req.name.iter_mut().zip(self.name.as_bytes()) {
            *dst = *b as libc::c_char;
        }
        // SAFETY: correctly shaped ifreq, outlives the call.
        if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut req as *mut IfReq) } < 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(Error::Radio(format!("SIOCGIFFLAGS {}: {e}", self.name)));
        }
        req.flags |= libc::IFF_UP as libc::c_short | libc::IFF_RUNNING as libc::c_short;
        // SAFETY: as above.
        if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &mut req as *mut IfReq) } < 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(Error::Radio(format!("SIOCSIFFLAGS {} up: {e}", self.name)));
        }

        // SAFETY: a NUL-terminated name built above.
        let idx = unsafe { libc::if_nametoindex(req.name.as_ptr()) };
        if idx == 0 {
            close(sock);
            return Err(Error::Radio(format!("if_nametoindex {}: not found", self.name)));
        }

        let addr = crate::tun::link_local(mac);
        let mut areq = In6IfReq { addr, prefixlen: 64, ifindex: idx as i32 };
        // SAFETY: in6_ifreq is the shape SIOCSIFADDR expects on an AF_INET6 socket.
        let rc = unsafe { libc::ioctl(sock, SIOCSIFADDR, &mut areq as *mut In6IfReq) };
        let err = std::io::Error::last_os_error();
        close(sock);
        if rc < 0 && err.raw_os_error() != Some(libc::EEXIST) {
            return Err(Error::Radio(format!(
                "SIOCSIFADDR {} {:?}: {err}",
                self.name,
                std::net::Ipv6Addr::from(addr)
            )));
        }
        Ok(std::net::Ipv6Addr::from(addr))
    }
}

fn addr_gen_mode_path(iface: &str) -> String {
    format!("/proc/sys/net/ipv6/conf/{iface}/addr_gen_mode")
}

/// The modified-EUI-64 link-local of a MAC.
///
/// Duplicated from `libawdl::data::link_local_from_mac` rather than depended on: the HAL
/// does not know about the protocol crate and should not start now. The rule is four lines
/// and `libawdl`'s copy is the one with the tests — public here so a test can hold the two
/// against each other, because a silent divergence would put the interface on an address
/// no peer computes.
pub fn link_local(mac: [u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    a
}
