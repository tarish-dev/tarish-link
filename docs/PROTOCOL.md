# How to run an AWDL experiment here

Written after two findings in one evening were published and then retracted. Both failures
were methodological, not technical, and both would have been caught by this page.

## What went wrong, so the rules have reasons

**Finding 38** proposed window breadth from three captures with one success, and a sweep
refuted it. The observation underneath was real; the mechanism guessed at was not.

**Finding 44** claimed the election is decided by metric, from a probe and its converse. The
converse ran **after** the probe, and the probe is what made the peers organise — so the
two arms measured different environments. It was written up as "the only experiment in this
document with a real control". It had a converse. That is not a control.

## The rules

1. **State the outcome measure before running.** Write down what counts as adoption, in
   frames, and do not adjust it afterwards. The measure used here: *at least 20 frames from
   a non-us sender naming our address as master, inside one capture.*

2. **Verify the starting state on the air, not from intent.** "The phones are settled" is a
   measurement — a pre-capture showing one device following another — not an assumption
   because they have been on a while. `awdl stats <cap>` before every run.

3. **Reset between runs.** Our own transmission changes the thing being measured. Every cell
   starts from AirDrop off on all Apple devices, air verified empty of Apple senders, then
   the condition is established fresh.

4. **Counterbalance the order.** Run conditions in an order that does not align with time, so
   drift over a session cannot masquerade as an effect.

5. **One variable per comparison, and say what the other variables were.** If the peers'
   cluster state changed between two runs, the runs are not comparable whatever else was held
   fixed.

6. **A result that does not replicate against a different device set is not a result.**
   Finding 44 survived a converse and died to a replication.

7. **Verify the manipulation took, in the capture, before reading the outcome.** Rule 2 is
   about the starting state; this is about whether the thing you did actually changed it.
   For a "forming" cell the check is `awdl timeline <cap>`: the peers must be **silent in
   the opening buckets** and then transition in — the `..*` signature. Peers talking in
   bucket 1 are settled peers, no matter what was done to the phones beforehand. Four
   consecutive FL runs were void on exactly this, and the fourth looked like a clean result
   refuting a hypothesis. See finding 46.

8. **Check OUR OWN preconditions, not only the peers'.** Rules 2 and 7 are about the room.
   These are about us, and every one of them has voided a run in this project:

   - **did we transmit?** A run that sent 7 frames in 75 s cannot be adopted and is not
     evidence of anything. Finding 56.
   - **were we synchronised?** `adopted=true`, spread under half a slot. Frames aimed with
     a bad phase land while the peer is on another channel, and *"the peer ignored us"* is
     then indistinguishable from *"the peer never heard us"*. Finding 55.
   - **did our frames reach the air?** Our own address must appear in the capture. The
     beacon's own counter says what we asked the radio to do, not what it did.

   `scripts/compete-trial.sh` enforces all of these and prints VOID with the reason rather
   than an outcome. A harness that can only produce a result is a harness that will produce
   a wrong one.

9. **Know how the peer wakes, and what it wakes as.** An idle iPhone advertises **no AWDL at
   all** — AirDrop set to Everyone on a phone sitting on a desk is zero frames on the air.
   A cold boot or Wi-Fi from fully-off wakes it as a **follower**; the Photos share sheet
   wakes it as a **master** that will capture the other peers. Waking a device is therefore
   part of the experimental condition, not a preparation step. Finding 61.

   Reset with **airplane mode**: the phones hold AWDL up for Continuity
   (`_applicationservicepairing`), not AirDrop, so switching AirDrop off does nothing.

10. **Establish the condition DURING the capture, never before it.** Two iPhones re-form a
   cluster in **under ten seconds**, and the harness needs about that long between starting
   the beacon and attaching `tcpdump`. So any toggle performed before the run has already
   expired when the first frame lands. Open the capture first, then have the operator act
   into it.

11. **An empty room refuses everything. Count the peers before reading the outcome.**
   *(Amended by finding 75: a SETTLED room is no longer a void for election work — a settled
   two-iPhone cluster was taken twice on 2026-09-14 with no entry event. The entry-event
   check below remains the right gate for experiments that DEPEND on entry, but a settled
   room is now a legitimate and cheaper condition in its own right. An EMPTY room is still a
   void, and that half is unchanged.)*
   A run with no peer transmitting produces zero frames naming us master, which is
   byte-for-byte the same observation as a peer that considered us and said no. Run E3
   spent eight minutes measuring an empty room and the garbage was confirmed on air, which
   made the zero look like the cleanest possible rejection. It was not a rejection; it was
   nobody. `compete-trial.sh` now VOIDs on it.

12. **The transmitter's own adoption counter is not the measurement — the capture is.**
   The beacon multiplexes receive against transmit on one socket, so its listening is
   whatever time the transmit schedule leaves over. That budget collapses to nothing in
   exactly the case worth measuring: once a competing cluster exists, the beacon adopts its
   clock and starts pacing against *that* master's windows. Run E3b's beacon reported 14
   adoptions where its capture held 2,123 from three peers. A passive `tcpdump` has no such
   conflict of interest and was right every time. Finding 70.

13. **Check the AirDrop mode, not just that the phone is awake — iOS reverts to Contacts.**
   An iPhone left alone returns to *Contacts Only* on its own, and in that state an idle
   handset advertises no AWDL at all: a 20-second capture of a room containing two unlocked
   phones came back with **zero** AWDL frames. That is indistinguishable from the phones
   being switched off, and it is the commonest reason a window opens onto silence.

   It does **not** invalidate an election result measured under it. AirDrop mode is an
   application-layer policy about who may send you a file; election is AWDL link-layer, and
   every outcome here is counted in frames where a peer named a master in its own tag 24. A
   phone transmitting AWDL in Contacts mode is making the same election decision. The
   preconditions that matter are the ones already enforced — peers transmitting, and a peer
   entering — and both are read off the air rather than off a screen.

## The harness

`scratchpad/trial.sh` — `LABEL=X FLAGS="..." ./trial.sh`. Four failure modes are designed
out of it, each of which produced a confident wrong answer before it was:

- a capture attached before `bring_up` recreates `mon0`, which then captures on a dead
  interface
- a failed capture leaving the previous run's file for `scp`, so four runs reported
  byte-identical results
- an ssh returning before its beacon exits, leaving two transmitters on one radio
- a wait loop on `pgrep -f` matching its own command line

Always print the capture's **hash and size** next to its result. Identical hashes across runs
mean the harness failed, not that the protocol is deterministic.

## Establishing a clean room is harder than it sounds

The forming cells need an air with no Apple senders on it, and **that state cannot be
produced on demand**. Within one hour, switching AirDrop off on every device gave a
completely silent channel once — 55 frames, all ours — and two minutes of continued
transmission the next time, from devices still naming each other as master.

Which of these explains it is not known: AWDL teardown may simply be slow; a Mac keeps
`awdl0` UP for Handoff, Sidecar and AirPlay regardless of the AirDrop setting; or another
Apple device in range that nobody thought about — a Watch, an iPad, an Apple TV — participates
without anyone touching AirDrop.

**And AWDL addresses rotate per session**, so a capture cannot even tell you how many distinct
devices are present, let alone which. Four different addresses appeared across four
consecutive twenty-second captures in a room believed to hold two phones.

The consequence for this protocol: **verify the empty room immediately before the run and
abort if it is not empty.** Do not assume a wait is sufficient, and do not infer device count
from addresses. If a clean room cannot be had, run only the cells that do not need one and
say which cells are missing — half a factorial reported as a factorial is how findings 38 and
44 happened.

## The open questions, and the design that settles them

### Q1. Does peer cluster state decide adoption, or does our metric?

Every adoption so far happened while peers were forming or joining; every refusal was against
a settled cluster; and our metric spanned 65 to 600 on both sides of that line. But metric and
state have never been varied independently.

**A 2x2, four runs, each from a clean reset:**

| cell | peers | our metric | cluster-state hypothesis predicts | metric hypothesis predicts |
|---|---|---|---|---|
| **FH** | forming | 600 | adopt | adopt |
| **FL** | forming | 50 | **adopt** | refuse |
| **SH** | settled | 600 | **refuse** | adopt |
| **SL** | settled | 50 | refuse | refuse |

The two hypotheses disagree in **FL** and **SH**. Those two cells are the experiment; FH and
SL are the sanity corners.

- *forming*: AirDrop off everywhere, air verified clean, our beacon started, **then** AirDrop
  switched on — so the peers join a channel we are already on.
- *settled*: AirDrop on, wait 60 s, verify on the air that one device follows another,
  **then** start our beacon.

Order: **SL, FH, SH, FL** — the two decisive cells sit third and fourth, and the two
hypotheses' predictions alternate, so neither can be produced by drift.

### Q2. Does the election comparison matter at all?

Only answerable if Q1 says metric matters. If cluster state decides, then a joining node
plausibly adopts whatever it hears without comparing, and `beats()` governs nothing we can
observe from outside — which would be worth knowing.

Counter-first is already refuted independently: a device carrying a counter 4500 times ours,
at distance 0 so that value was its own `master_counter`, adopted us anyway.

### Q3. What does a settled cluster respond to at all?

If SH refuses — the highest metric in the room against a settled cluster — then nothing we
advertise moves it, and the question becomes whether anything does: joining its schedule
(`--follow`), matching its master's address ordering, or waiting for its master to leave.
That is a separate design and should not be smuggled into Q1.

## What to do with a negative

Record it at the strength it has. "Six runs, metrics 65 to 600, no adoption" is a finding.
"Metric does not matter" is not, until metric has been varied with everything else held.
