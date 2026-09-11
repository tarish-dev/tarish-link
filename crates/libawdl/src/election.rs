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
    /// The node this one is following.
    pub master: [u8; 6],
    /// The master's metric, as this node understands it.
    pub master_metric: u32,
    /// This node's own metric — its claim to the job.
    pub self_metric: u32,
    /// Present only in a private election.
    pub private_master: Option<[u8; 6]>,
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
            // v[4] is unnamed upstream and left undecoded rather than guessed at.
            master: v.get(5..11)?.try_into().ok()?,
            master_metric: le::u32(v, 11)?,
            self_metric: le::u32(v, 15)?,
            // A private election appends two unknown bytes then a second address.
            private_master: if flags != 0 {
                v.get(21..27).and_then(|b| b.try_into().ok())
            } else {
                None
            },
        })
    }

    /// Whether this node is claiming the job rather than following someone.
    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
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
            // v[28..32] unknown, v[32..36] reserved upstream.
            self_counter: le::u32(v, 36)?,
        })
    }

    pub fn claims_mastership(&self) -> bool {
        self.distance == 0
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
