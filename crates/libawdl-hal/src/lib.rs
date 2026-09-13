//! The contract between an AWDL implementation and the radio underneath it.
//!
//! # Why this exists
//!
//! AWDL works on Pixels because Google ships two binaries in the vendor image: a closed
//! userspace library that speaks the protocol, and a kernel module that presents the
//! radio to it. Neither is available anywhere else, so AirDrop-compatible sharing is
//! confined to hardware one company chooses.
//!
//! This crate is the seam. Above it, everything is portable and ours. Below it is the
//! part only a vendor can supply — driver and firmware — reduced to the **smallest
//! surface that a working implementation has been observed to need**.
//!
//! ```text
//!   share sheet, transfers, AirDrop protocol      portable
//!   AWDL protocol engine (replaces libmosey)      portable
//!  ───────────────────── this crate ─────────────────────
//!   driver + firmware                             vendor
//! ```
//!
//! # The surface is not invented
//!
//! It would be easy to design an ideal radio API and hand vendors an impossible list.
//! Instead this mirrors the vendor command set of `wonder.ko`, Google's own shim, which
//! was recovered from the module's symbols on a shipping device:
//!
//! | `wonder.ko` vendor command | here |
//! |---|---|
//! | `get_cap` | [`Radio::capabilities`] |
//! | `set_reg` | [`Radio::set_regulatory`] |
//! | `set_frequency` | [`Radio::set_channel`] |
//! | `set_filter` | [`Radio::set_rx_filter`] |
//! | `set_fixed_tx_rate` | [`TxParams`] |
//! | `get_if_mac_addr` | [`Radio::mac_address`] |
//! | `get_mac_tsf` | [`Radio::tsf`] |
//! | `set_channel_schedule_req` | [`Radio::set_channel_schedule`] |
//!
//! Eight operations. Google shipped a product on exactly this surface, which is the
//! best evidence available that it is sufficient — and, just as usefully, that nothing
//! larger is required.
//!
//! # What a vendor gets for implementing it
//!
//! [`Caps::tier`] answers "how well will this chip do AWDL" before a line of protocol
//! code runs, and [`Caps::gaps_to_hw_timed`] turns a "no" into a numbered list of
//! missing primitives. That is deliberate: an unimplementable spec gets ignored, a
//! spec that says *these four things are missing* gets worked on.

pub mod caps;

/// Linux-only at runtime -- it shells out to `iw` -- but it compiles everywhere on
/// purpose, so the seam is type-checked on whatever machine the work happens on.
pub mod nl80211;

/// Injection and capture. Genuinely Linux-only: `AF_PACKET` has no equivalent elsewhere,
/// so unlike `nl80211` this one is compiled out rather than stubbed.
#[cfg(target_os = "linux")]
pub mod rawsock;

/// The `awdl0` netdev. Linux-only: this is `/dev/net/tun` and a `TUNSETIFF` ioctl, and
/// there is no portable equivalent worth pretending about.
#[cfg(target_os = "linux")]
pub mod tun;

/// Waiting on the radio and the netdev together. A syscall, so it belongs here rather
/// than giving the CLI a `libc` dependency to run its loop.
#[cfg(target_os = "linux")]
pub mod poll;

pub use caps::{Caps, Tier, TsfPrecision, SOCIAL_CHANNELS};

/// A MAC TSF reading, microseconds, as the radio reports it.
///
/// AWDL synchronisation is anchored to this and to nothing else. It is **not** the
/// host's clock and must never be substituted with one: the host clock is not what the
/// peer is synchronised to, and the error is invisible until a cluster fails to hold.
pub type Tsf = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The radio cannot do this at all. Not a failure — a fact to route around, which
    /// is why it names the capability rather than just saying no.
    Unsupported(&'static str),
    /// The regulatory domain forbids it. Distinct from `Unsupported` because it is
    /// fixable by configuration, and because it is the single most common reason a
    /// capable radio refuses to transmit on channel 44 or 149.
    RegulatoryDenied { channel: u8 },
    /// The radio or driver rejected a well-formed request.
    Radio(String),
    /// A request that was valid when issued no longer is — an interface went down, a
    /// schedule anchor has already passed.
    Stale(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// How a frame should be transmitted.
///
/// AWDL pins these rather than letting rate control choose, and the reason is timing
/// rather than throughput: a synchronisation frame whose air time varies perturbs the
/// very measurement it exists to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxParams {
    pub mcs: u8,
    pub nss: u8,
    /// 0 = 20 MHz, 1 = 40, 2 = 80.
    pub bandwidth: u8,
    /// Short guard interval.
    pub short_gi: bool,
}

impl Default for TxParams {
    /// The conservative choice: lowest MCS, one spatial stream, 20 MHz, long GI.
    ///
    /// Sync frames want range and predictability, not speed. A captured Apple device
    /// was observed at `Pre=2, Mcs=3, Gi=2, Bw=2` for data, but its action frames sit
    /// far lower, and matching that is a measurement to make rather than a guess to
    /// ship — so the default here is the safe one.
    fn default() -> Self {
        TxParams { mcs: 0, nss: 1, bandwidth: 0, short_gi: false }
    }
}

/// One entry in an AWDL channel schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub channel: u8,
    /// How long to stay, microseconds. AWDL's Availability Window is 16 TU = 16384 µs.
    pub dwell_us: u32,
}

/// A frame as it came off the air, with the metadata that makes it usable.
#[derive(Debug, Clone)]
pub struct RxFrame {
    pub bytes: Vec<u8>,
    /// When the KERNEL saw the frame, microseconds since the epoch.
    ///
    /// Distinct from `tsf`, which is the radio's own clock and is absent on most adapters
    /// (0 of 801 frames on the MT7612U). This is the next best thing and it is much better
    /// than the caller's own clock: reading `Instant::now()` after `recv` measures when the
    /// process got round to it, so a socket backlog is added to every frame behind it.
    pub host_us: Option<u64>,
    /// The radio's TSF at reception. **Without this the frame is nearly useless for
    /// synchronisation**, which is why it is not an afterthought in the struct.
    pub tsf: Option<Tsf>,
    pub freq_mhz: Option<u16>,
    pub signal_dbm: Option<i8>,
}

/// The radio, as an AWDL implementation needs to see it.
///
/// Implementors: a method you cannot support must return
/// [`Error::Unsupported`] rather than silently doing nothing. The layer above adapts
/// to a missing capability and cannot adapt to a lie.
pub trait Radio {
    fn capabilities(&self) -> Result<Caps>;

    /// The MAC address AWDL frames will be sent from.
    ///
    /// Expected to be locally administered and to change: every AWDL sender observed in
    /// our captures randomises it. Callers must not treat it as an identity.
    fn mac_address(&self) -> Result<[u8; 6]>;

    /// Apply a regulatory domain.
    ///
    /// Call this **before** probing channels. A radio in `country 00` reports 44 and
    /// 149 as present and refuses to transmit on them, and a capability probe run
    /// beforehand will cheerfully report a radio that cannot do the job.
    fn set_regulatory(&mut self, country: [u8; 2]) -> Result<()>;

    /// Switch channel now.
    fn set_channel(&mut self, channel: u8) -> Result<()>;

    /// Read the MAC's TSF.
    fn tsf(&self) -> Result<Tsf>;

    /// Hand the radio a channel schedule anchored to a TSF value, to execute itself.
    ///
    /// **This one method is the difference between [`Tier::HwTimed`] and
    /// [`Tier::SoftTimed`]**, and therefore between synchronisation that holds under
    /// load and synchronisation that is only as good as the host scheduler. A radio
    /// that cannot do it returns [`Error::Unsupported`] and the layer above falls back
    /// to driving [`Radio::set_channel`] on a timer — which works, and is what OWL
    /// does, and is measurably worse.
    fn set_channel_schedule(&mut self, slots: &[Slot], anchor: Tsf) -> Result<()>;

    /// Transmit one 802.11 frame.
    fn tx(&mut self, frame: &[u8], params: TxParams) -> Result<()>;

    /// Receive one frame, blocking until one arrives or the timeout expires.
    fn rx(&mut self, timeout_ms: u32) -> Result<Option<RxFrame>>;

    /// Ask the radio to drop uninteresting frames before waking the host.
    ///
    /// Optional, and purely about power. In our first capture 6287 of 6584 frames were
    /// ACKs the host had to look at and discard.
    fn set_rx_filter(&mut self, _keep_types: &[(u8, u8)]) -> Result<()> {
        Err(Error::Unsupported("rx filter offload"))
    }
}
