//! Waiting on the radio and the netdev at once.
//!
//! The data plane has exactly two sources of work — a packet from the kernel, or a frame
//! from the air — and must not block on one while the other has something ready. Two
//! threads would need a lock around a radio that can only transmit one frame at a time
//! anyway, so a single `poll` over both descriptors is both simpler and closer to what the
//! hardware can actually do.
//!
//! This lives in the HAL because it is a syscall. The CLI has no `libc` dependency and
//! should not acquire one to run a loop.

use crate::Result;
use std::os::fd::RawFd;

/// Which of the two descriptors became readable. Both can, in the same call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    pub first: bool,
    pub second: bool,
}

impl Ready {
    pub fn neither(&self) -> bool {
        !self.first && !self.second
    }
}

/// Block until either descriptor is readable, or the timeout expires.
///
/// A timeout of 0 polls without blocking; a negative one blocks indefinitely, which the
/// data plane must not do — it has a deadline to honour and statistics to print.
///
/// `EINTR` is reported as "neither ready" rather than as an error. A signal arriving during
/// a poll is not a failure and the caller's loop will simply go round again; treating it as
/// an error means any `SIGWINCH` from resizing a terminal kills the data plane.
pub fn wait_readable(first: RawFd, second: RawFd, timeout_ms: i32) -> Result<Ready> {
    let mut fds = [
        libc::pollfd { fd: first, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: second, events: libc::POLLIN, revents: 0 },
    ];
    // SAFETY: two initialised pollfds, and the count matches the array length.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return Ok(Ready { first: false, second: false });
        }
        return Err(crate::Error::Radio(format!("poll: {e}")));
    }
    // POLLERR and POLLHUP arrive in revents whether or not they were requested, and both
    // mean the next read will tell the caller what happened -- so they count as readable
    // rather than being silently ignored, which would spin.
    let readable = |p: &libc::pollfd| {
        p.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0
    };
    Ok(Ready { first: readable(&fds[0]), second: readable(&fds[1]) })
}
