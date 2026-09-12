//! Election Parameters (tag 5) and Election Parameters v2 (tag 24).
//!
//! AWDL has no configured master. Every node advertises a **metric** and the address of
//! whoever it currently believes is master, and the cluster converges on the strongest
//! claim. There is no handshake and no acknowledgement: a node simply starts naming a
//! different master, and its neighbours follow or do not.
//!
//! Both tags are present in every frame observed — a device advertises v1 and v2
//! simultaneously, presumably so older peers can still follow it. They do not carry the
//! same fields, and v2 is not merely v1 with more bits, so both are decoded.

use crate::le;

/// Election Parameters (tag 5). The original form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionParams {
    /// Non-zero means a private election, which appends two more fields.
    pub flags: u8,
    pub id: u16,
    /// Hops to the master. 0 means "I am the master".
    pub distance: u8,
    /// Byte 4, unnamed upstream. Zero everywhere measured, carried so a rebuild is exact.
    pub reserved_4: u8,
    /// The node this one is following.
    pub master: [u8; 6],
    /// The master's metric, as this node understands it.
    pub master_metric: u32,
    /// This node's own metric — its claim to the job.
    pub self_metric: u32,
    /// Present only in a private election.
    pub private_master: Option<[u8; 6]>,
    /// Everything after byte 19.
    ///
    /// **The tag is 21 bytes on the wire, not the 19 this struct's fields account for** —
    /// every one of the 42 distinct values across `captures/` is 21, from Apple and
    /// `libmosey` alike, with two zero bytes on the end. A private election is said to
    /// append more here; none has ever been captured, so rather than encode a layout
    /// nobody has seen, the remainder is carried whole and put back unchanged.
    pub tail: Vec<u8>,
}

impl ElectionParams {
    pub const MIN_LEN: usize = 19;

    pub fn parse(v: &[u8]) -> Option<ElectionParams> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        let flags = le::u8(v, 0)?;
        Some(ElectionParams {
            flags,
            id: le::u16(v, 1)?,
            distance: le::u8(v, 3)?,
            reserved_4: le::u8(v, 4)?,
            master: v.get(5..11)?.try_into().ok()?,
            master_metric: le::u32(v, 11)?,
            self_metric: le::u32(v, 15)?,
            // A private election appends two unknown bytes then a second address.
            private_master: if flags != 0 {
                v.get(21..27).and_then(|b| b.try_into().ok())
            } else {
                None
            },
            tail: v.get(Self::MIN_LEN..).unwrap_or(&[]).to_vec(),
        })
    }

    /// Whether this node is claiming the job rather than following someone.
    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
    }

    /// Serialise back to the wire: the 19 named bytes, then whatever followed them.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MIN_LEN + self.tail.len());
        out.push(self.flags);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(self.distance);
        out.push(self.reserved_4);
        out.extend_from_slice(&self.master);
        out.extend_from_slice(&self.master_metric.to_le_bytes());
        out.extend_from_slice(&self.self_metric.to_le_bytes());
        debug_assert_eq!(out.len(), Self::MIN_LEN);
        out.extend_from_slice(&self.tail);
        out
    }

    /// A claim of our own: master of a cluster of one.
    ///
    /// `distance` 0 and `master` set to our own address is what "I am the master" looks
    /// like — there is no separate flag for it. A node that advertises this and then meets
    /// a stronger peer simply starts naming that peer instead; see
    /// [`ElectionParamsV2::beats`] for what stronger means, which is not what the paper
    /// says it is.
    pub fn claiming(addr: [u8; 6], metric: u32) -> ElectionParams {
        ElectionParams {
            flags: 0,
            id: 0,
            distance: 0,
            reserved_4: 0,
            master: addr,
            master_metric: metric,
            self_metric: metric,
            private_master: None,
            // Two zero bytes: the shape every captured frame has.
            tail: vec![0, 0],
        }
    }
}

/// Election Parameters v2 (tag 24).
///
/// Carries counters v1 has no room for.
///
/// **The counters do not order the election** — see [`ElectionParamsV2::beats`]. Their
/// observed values are wildly inconsistent between devices in one capture (68364, 608,
/// 155, 0), which rules out a cluster-wide clock as well. Their meaning is unresolved
/// and deliberately not guessed at here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionParamsV2 {
    pub master: [u8; 6],
    /// A second address whose role is not documented. Observed equal to the sender's
    /// own address in every frame checked, but that is an observation and not a rule.
    pub other: [u8; 6],
    pub master_counter: u32,
    pub distance: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    /// Bytes 28..32, unnamed, and 32..36, reserved upstream. Zero in every frame
    /// measured; carried rather than assumed so a rebuild is exact either way.
    pub unknown_28: [u8; 8],
    pub self_counter: u32,
}

impl ElectionParamsV2 {
    pub const MIN_LEN: usize = 40;

    pub fn parse(v: &[u8]) -> Option<ElectionParamsV2> {
        if v.len() < Self::MIN_LEN {
            return None;
        }
        Some(ElectionParamsV2 {
            master: v.get(0..6)?.try_into().ok()?,
            other: v.get(6..12)?.try_into().ok()?,
            master_counter: le::u32(v, 12)?,
            distance: le::u32(v, 16)?,
            master_metric: le::u32(v, 20)?,
            self_metric: le::u32(v, 24)?,
            unknown_28: v.get(28..36)?.try_into().ok()?,
            self_counter: le::u32(v, 36)?,
        })
    }

    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
    }

    /// Serialise back to the wire. Exactly 40 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MIN_LEN);
        out.extend_from_slice(&self.master);
        out.extend_from_slice(&self.other);
        out.extend_from_slice(&self.master_counter.to_le_bytes());
        out.extend_from_slice(&self.distance.to_le_bytes());
        out.extend_from_slice(&self.master_metric.to_le_bytes());
        out.extend_from_slice(&self.self_metric.to_le_bytes());
        out.extend_from_slice(&self.unknown_28);
        out.extend_from_slice(&self.self_counter.to_le_bytes());
        debug_assert_eq!(out.len(), Self::MIN_LEN);
        out
    }

    /// The v2 half of a claim of our own, to accompany [`ElectionParams::claiming`].
    ///
    /// Both tags go in every frame: a device advertises v1 and v2 together, and sending
    /// one without the other is a shape no real device has.
    ///
    /// `counter` is passed in rather than invented because its meaning is unresolved — see
    /// the type's own note. It is not the election's ordering term, so a wrong value here
    /// does not lose an election, but making one up would put a number on the air that
    /// claims to mean something we cannot describe.
    pub fn claiming(addr: [u8; 6], metric: u32, counter: u32) -> ElectionParamsV2 {
        ElectionParamsV2 {
            master: addr,
            other: addr,
            master_counter: counter,
            distance: 0,
            master_metric: metric,
            self_metric: metric,
            unknown_28: [0; 8],
            self_counter: counter,
        }
    }

    /// Would this node's claim beat `other`'s?
    ///
    /// **Metric first, then address.** The counter is deliberately NOT the leading term,
    /// and an earlier version of this function had it first on the strength of the
    /// paper's "(counter, metric, address)" phrasing. A capture refuted that:
    ///
    /// ```text
    /// 6a:89:d8:a5:88:9b   metric 510   counter 68364   ->  followed be:35
    /// be:35:be:c9:05:1f   metric 520   counter   608   ->  won
    /// ```
    ///
    /// The node with a counter more than a hundred times larger yielded to the one with
    /// the higher metric. Whatever the counter orders, it is not this.
    ///
    /// Address breaks a metric tie. That part is still inferred rather than observed —
    /// no capture so far has contained two nodes with equal metrics.
    pub fn beats(&self, other: &ElectionParamsV2, self_addr: [u8; 6], other_addr: [u8; 6]) -> bool {
        (self.self_metric, self_addr) > (other.self_metric, other_addr)
    }
}
