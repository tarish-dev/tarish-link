//! Injection and capture on a monitor interface, via `AF_PACKET`.
//!
//! This is the only part of the HAL that actually touches the air. Everything else
//! shells out to `iw` to *configure* a radio; this hands bytes to it.
//!
//! # Why a raw socket rather than nl80211
//!
//! nl80211 has no frame-injection path for arbitrary 802.11. A monitor interface on
//! Linux is an `AF_PACKET` device whose frames are radiotap-prefixed in both directions,
//! so a `SOCK_RAW` socket bound to it is the whole mechanism — and it is what `aireplay`
//! and OWL use, which matters because those are the two implementations known to work on
//! this hardware.
//!
//! # The radiotap header on TX is not optional, even when empty
//!
//! Writing a bare 802.11 frame to a monitor interface does not transmit it — the driver
//! reads a radiotap header first and will reject or mangle a frame without one. An
//! eight-byte header with an empty presence bitmap is valid and means "you choose the
//! rate", which is what we want until [`crate::TxParams`] is measured against a real
//! Apple device rather than guessed.
//!
//! # The trap that costs an evening
//!
//! `send()` returning `EAGAIN` on a monitor interface almost never means "buffer full".
//! On mt76 it means **another vif on the same phy is up** — see `bring_up`. The adapter
//! is fine, `aireplay-ng -9` passes, and nothing appears in `dmesg`. That failure is
//! recorded in `awdl-up.sh` on the research Pi and in OWL's own notes; the error text
//! here names it so nobody has to rediscover it.

use crate::{Error, Result};

/// A minimal radiotap header: version 0, no fields present.
///
/// `len` is little-endian and counts itself, so eight bytes total: version, pad, len,
/// and a zero presence word.
pub const RADIOTAP_EMPTY: [u8; 8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];

/// A raw socket bound to one monitor interface.
pub struct RawSock {
    fd: i32,
    iface: String,
}

impl RawSock {
    /// Open and bind to `iface`.
    ///
    /// Requires `CAP_NET_RAW`, which in practice means root. The error says so, because
    /// the kernel's own message for it is `Operation not permitted` on a socket call and
    /// reads like a bug rather than a missing privilege.
    pub fn open(iface: &str) -> Result<RawSock> {
        // ETH_P_ALL in network byte order, as the protocol argument wants.
        const ETH_P_ALL: u16 = 0x0003;
        let fd = unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(ETH_P_ALL.to_be()))
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Radio(format!(
                "AF_PACKET socket on {iface}: {e} — this needs CAP_NET_RAW, i.e. root"
            )));
        }

        let idx = if_nametoindex(iface)?;
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = idx as i32;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Radio(format!("bind to {iface}: {e}")));
        }
        Ok(RawSock { fd, iface: iface.to_string() })
    }

    /// Transmit one 802.11 frame, prefixing the radiotap header the driver requires.
    pub fn tx(&self, frame: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(RADIOTAP_EMPTY.len() + frame.len());
        buf.extend_from_slice(&RADIOTAP_EMPTY);
        buf.extend_from_slice(frame);
        let n = unsafe {
            libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAGAIN) {
                return Err(Error::Radio(format!(
                    "send on {}: EAGAIN. On mt76 this means ANOTHER VIF ON THE SAME PHY IS \
                     UP, not that a buffer is full — bring the managed interface down. The \
                     adapter is fine and dmesg will say nothing.",
                    self.iface
                )));
            }
            return Err(Error::Radio(format!("send on {}: {e}", self.iface)));
        }
        if (n as usize) != buf.len() {
            return Err(Error::Radio(format!(
                "short write on {}: {n} of {} bytes",
                self.iface,
                buf.len()
            )));
        }
        Ok(())
    }

    /// Set a receive timeout so [`rx`](Self::rx) cannot block forever.
    pub fn set_rx_timeout(&self, ms: u32) -> Result<()> {
        let tv = libc::timeval {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if rc < 0 {
            return Err(Error::Radio(format!("SO_RCVTIMEO: {}", std::io::Error::last_os_error())));
        }
        Ok(())
    }

    /// Receive one frame as it came off the air, radiotap header included.
    ///
    /// `Ok(None)` means the timeout expired with nothing to read, which is the normal
    /// case on a quiet channel and not an error.
    pub fn rx(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) => Ok(None),
                _ => Err(Error::Radio(format!("recv on {}: {e}", self.iface))),
            };
        }
        Ok(Some(n as usize))
    }
}

impl Drop for RawSock {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn if_nametoindex(iface: &str) -> Result<u32> {
    let c = std::ffi::CString::new(iface).map_err(|_| Error::Radio("bad interface name".into()))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(Error::Radio(format!(
            "no interface {iface}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(idx)
}

/// So one event loop can wait on this and the tun together.
///
/// A blocking read on either descriptor starves the other, and two threads would need a
/// lock around the radio. `poll` on both is the smallest arrangement that works.
impl std::os::fd::AsRawFd for RawSock {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}
