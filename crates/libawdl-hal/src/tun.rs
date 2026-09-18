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

/// A **TAP**, not a TUN — an Ethernet interface, on purpose. A TUN carries bare IP but has no
/// link-layer address (`ARPHRD_NONE`), and `tarishsharingd` derives its AirDrop instance name
/// from the interface's MAC; on a MAC-less TUN that came out `000000000000`, which Apple will
/// not display (finding 98). A TAP has a settable MAC, so we can give it the AWDL address, the
/// instance name is real, and the kernel's own EUI-64 link-local matches the derived one. The
/// cost is a 14-byte Ethernet header on every frame, which `libawdl-session` strips inbound and
/// prepends outbound.
#[allow(dead_code)]
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
/// No packet-information prefix. Without this every read is preceded by four bytes of
/// flags and protocol.
const IFF_NO_PI: libc::c_short = 0x1000;

/// `SIOCSIFHWADDR` — set the link-layer address. In `tarishd`'s allowed `udp_socket` ioctl
/// xperms (0x8924), so setting the TAP's MAC stays inside its SELinux policy.
const SIOCSIFHWADDR: IoctlReq = 0x8924;
/// `ARPHRD_ETHER`, the `sa_family` an Ethernet hardware address carries.
const ARPHRD_ETHER: u16 = 1;

/// The type `libc::ioctl` takes for its request argument: `c_ulong` on glibc, but `c_int` on
/// Android's bionic. Same numeric values (all fit in i32); only the declared type differs.
#[cfg(target_os = "android")]
type IoctlReq = libc::c_int;
#[cfg(not(target_os = "android"))]
type IoctlReq = libc::c_ulong;

/// `TUNSETIFF`. `_IOW('T', 202, int)`, and it is 32-bit on every Linux architecture.
const TUNSETIFF: IoctlReq = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    flags: libc::c_short,
    // The real `ifreq` is a union large enough for a sockaddr; only the flags are read for
    // TUNSETIFF, but the kernel copies the whole thing, so it has to be the full size.
    pad: [u8; 22],
}

/// `ifreq` shaped for `SIOCSIFHWADDR`: the union holds a `sockaddr` (family + 14 bytes), of
/// which the first six after the family are the MAC.
#[repr(C)]
struct IfReqHw {
    name: [libc::c_char; libc::IF_NAMESIZE],
    sa_family: u16,
    mac: [u8; 6],
    pad: [u8; 8],
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
            flags: IFF_TAP | IFF_NO_PI,
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
const SIOCGIFFLAGS: IoctlReq = 0x8913;
const SIOCSIFFLAGS: IoctlReq = 0x8914;
const SIOCSIFADDR: IoctlReq = 0x8916;

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
        // ifindex first (a bare syscall, always permitted), so addr_gen_mode can be set over
        // netlink below.
        let cname = std::ffi::CString::new(self.name.as_str())
            .map_err(|_| Error::Radio("bad interface name".into()))?;
        // SAFETY: cname is NUL-terminated.
        let ifidx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifidx == 0 {
            return Err(Error::Radio(format!("if_nametoindex {}: not found", self.name)));
        }
        // addr_gen_mode = none, BEFORE the interface comes up (it is read once, at that point).
        // Set over rtnetlink, not /proc/sys: a TUN has no MAC, so without mode 1 the kernel
        // adds a stable-privacy link-local beside our derived one and may prefer it as the
        // source. The /proc write is denied under `tarishd`'s SELinux policy (`proc_net`),
        // while rtnetlink (`RTM_NEWLINK` + `IFLA_AF_SPEC`) is allowed — and is what libmosey
        // does.
        set_addr_gen_mode_none(ifidx)?;

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

        // Give the TAP the AWDL MAC, while it is still down. This is what makes the interface
        // carry a real hardware address: the daemon's AirDrop instance name derives from it,
        // and the kernel's EUI-64 link-local then matches the derived one.
        let mut hw = IfReqHw {
            name: [0; libc::IF_NAMESIZE],
            sa_family: ARPHRD_ETHER,
            mac,
            pad: [0; 8],
        };
        for (dst, b) in hw.name.iter_mut().zip(self.name.as_bytes()) {
            *dst = *b as libc::c_char;
        }
        // SAFETY: correctly shaped ifreq for SIOCSIFHWADDR, outlives the call.
        if unsafe { libc::ioctl(sock, SIOCSIFHWADDR, &mut hw as *mut IfReqHw) } < 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(Error::Radio(format!("SIOCSIFHWADDR {} {mac:02x?}: {e}", self.name)));
        }

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

/// Append one netlink attribute (`nla_len`, `nla_type`, data, 4-byte pad).
fn push_nlattr(v: &mut Vec<u8>, atype: u16, data: &[u8]) {
    let len = 4 + data.len();
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&atype.to_ne_bytes());
    v.extend_from_slice(data);
    let pad = (4 - (len % 4)) % 4;
    v.extend(std::iter::repeat(0u8).take(pad));
}

/// Set `addr_gen_mode = none` on an interface over rtnetlink, the equivalent of writing 1 to
/// `/proc/sys/net/ipv6/conf/<if>/addr_gen_mode` but without touching `proc_net` (denied under
/// `tarishd`'s SELinux policy). `RTM_NEWLINK` with `IFLA_AF_SPEC` → `AF_INET6` →
/// `IFLA_INET6_ADDR_GEN_MODE`. The socket is unbound (auto-bind on send), as libmosey's is.
fn set_addr_gen_mode_none(ifindex: u32) -> Result<()> {
    const RTM_NEWLINK: u16 = 16;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLMSG_ERROR: u16 = 2;
    const IFLA_AF_SPEC: u16 = 26;
    const AF_INET6_ATTR: u16 = 10;
    const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
    const IN6_ADDR_GEN_MODE_NONE: u8 = 1;

    // Innermost first: ADDR_GEN_MODE = none, wrapped in AF_INET6, wrapped in AF_SPEC.
    let mut inet6 = Vec::new();
    push_nlattr(&mut inet6, IFLA_INET6_ADDR_GEN_MODE, &[IN6_ADDR_GEN_MODE_NONE]);
    let mut afspec = Vec::new();
    push_nlattr(&mut afspec, AF_INET6_ATTR, &inet6);

    // ifinfomsg: family(u8) pad(u8) type(u16) index(i32) flags(u32) change(u32).
    let mut body = Vec::new();
    body.push(0); // AF_UNSPEC
    body.push(0); // pad
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes()); // flags
    body.extend_from_slice(&0u32.to_ne_bytes()); // change
    push_nlattr(&mut body, IFLA_AF_SPEC, &afspec);

    let total = 16 + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as u32).to_ne_bytes());
    msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&body);

    // SAFETY: a short-lived rtnetlink socket, closed before return.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(Error::Radio(format!(
            "addr_gen_mode: netlink socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst.nl_family = libc::AF_NETLINK as u16;
    let n = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(Error::Radio(format!("addr_gen_mode: send: {e}")));
    }
    let mut rbuf = [0u8; 256];
    let r = unsafe { libc::recv(fd, rbuf.as_mut_ptr() as *mut libc::c_void, rbuf.len(), 0) };
    unsafe { libc::close(fd) };
    if r >= 20 && u16::from_ne_bytes([rbuf[4], rbuf[5]]) == NLMSG_ERROR {
        let code = i32::from_ne_bytes([rbuf[16], rbuf[17], rbuf[18], rbuf[19]]);
        if code != 0 {
            return Err(Error::Radio(format!(
                "addr_gen_mode: kernel rejected it: {}",
                std::io::Error::from_raw_os_error(-code)
            )));
        }
    }
    Ok(())
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
