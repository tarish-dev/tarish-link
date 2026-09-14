#!/bin/bash
# ONE ELECTION TRIAL, with its own validity checks.
#
# Every void run in this project looked like a result until something extra was checked by
# hand afterwards. So the checks are here, they run before the outcome is read, and a trial
# that fails any of them prints VOID and never shows a number that could be quoted.
#
#   VOID    a precondition failed. There is no result, and the reason is named
#   ADOPT   >= 20 frames from a non-us sender naming our address as master
#   REFUSE  the preconditions held and nobody adopted us
#
# The outcome measure is pre-registered in docs/PROTOCOL.md and is not adjusted here.
set -u
PI=${PI:-pi@raspberrypi.local}
MON=${MON:-mon0}
MANAGED=${MANAGED:-wlx00c0cab0604c}
OURMAC=${OURMAC:-00:c0:ca:b0:60:4c}
CHAN=${CHAN:-149}
METRIC=${METRIC:-600}
SECS=${SECS:-75}
CAPS=${CAPS:-60}
LABEL=${LABEL:-compete}
# A --garbage spec, or empty for a clean control run. Everything the E-series measured was
# run by hand instead of through here, and it cost a voided run (E3, into an empty room)
# plus an evening reconciling the beacon's own adoption counter against the capture. The
# validity gate below catches both of those before a number gets quoted.
GARBAGE=${GARBAGE:-}

R=/tmp/ct_$LABEL
ssh -o ConnectTimeout=10 "$PI" "
set -u
cd ~/tarish-libawdl
sudo killall awdl tcpdump 2>/dev/null; sleep 1

# DELETE LAST RUN'S ARTIFACTS FIRST. $R is derived from $LABEL, so a re-run with the same
# label lands on the same paths -- and every read below (`stats $R.pcap`, the tag dump, the
# "room before") happily reads a file that this run never wrote. A Z1 re-run reported the
# previous Z1's capture verbatim, down to "seen 9x, first at frame 100", while its own
# tcpdump had not started at all. It voided for other reasons and the staleness was caught
# by the byte-identical dump; it could just as easily have reported a stale ADOPT.
rm -f $R.pcap $R.before.pcap $R.log $R.before.txt $R.timeline.txt $R.tcpdump.err

# BEFORE: is the room a settled cluster at all? A trial against an empty or churning room
# measures nothing, and both look like a clean refusal afterwards.
sudo timeout 12 tcpdump -i $MON -w $R.before.pcap -s0 2>>$R.tcpdump.err
./target/release/awdl stats $R.before.pcap 2>&1 | grep -A8 'who names whom' > $R.before.txt
./target/release/awdl timeline $R.before.pcap 2>&1 | sed -n '3,12p' > $R.timeline.txt

(sudo ./target/release/awdl beacon $MANAGED $MON $CHAN $SECS 2 --follow --metric $METRIC --tenure 99999 ${GARBAGE:+--garbage $GARBAGE} > $R.log 2>&1 &)
for i in \$(seq 1 15); do ip link show $MON >/dev/null 2>&1 && break; sleep 1; done
sleep 4
sudo timeout $CAPS tcpdump -i $MON -w $R.pcap -s0 2>>$R.tcpdump.err
sleep 12
"

fetch() { ssh -o ConnectTimeout=10 "$PI" "cat $1" 2>/dev/null; }

echo "=================== ROOM BEFORE ==================="
fetch $R.before.txt
echo "--- timeline (settled = no '.' then '*' arrival) ---"
fetch $R.timeline.txt

echo
echo "=================== OUR RUN ==================="
LOG=$(fetch $R.log)
echo "$LOG" | grep -E '^sent|^cluster|^datapath'

SENT=$(echo "$LOG" | grep -oE '^sent [0-9]+ MIF, [0-9]+ PSF' | grep -oE '[0-9]+' | awk '{n+=$1} END {print n+0}')
ADOPTED=$(echo "$LOG" | grep -oE 'adopted=(true|false)' | tail -1 | cut -d= -f2)
SPREAD=$(echo "$LOG" | grep -oE 'spread Some\([0-9]+\)' | tail -1 | grep -oE '[0-9]+')
CHANGES=$(echo "$LOG" | grep -oE '[0-9]+ master change' | grep -oE '[0-9]+')

echo
echo "=================== VALIDITY ==================="
VOID=""
# A. did this run produce a capture of its own? With $R.pcap deleted up front, its absence
#    means tcpdump never ran or died -- which is a void, not an empty room, and the two
#    were indistinguishable in the output until a stale file gave it away.
CAPOK=$(ssh -o ConnectTimeout=10 "$PI" "[ -s $R.pcap ] && echo yes || echo no")
[ "$CAPOK" = "yes" ] || VOID="$VOID
  no capture from this run at $R.pcap. tcpdump did not run or died; see $R.tcpdump.err
  on the Pi. Nothing below was measured."
# B. did we actually transmit? A starved run cannot be adopted and is not evidence.
# RATE, not a flat count. 40 frames passed this check for a 420-second run that was
# out-transmitted 2884 to 151 and voided; the healthy rate is one frame per advertised
# window, three windows per 1.049 s cycle, so ~2.8/s. Anything under 2/s is starved.
MINSENT=$(awk -v s="$SECS" 'BEGIN {print int(s * 2)}')
[ "${SENT:-0}" -ge "$MINSENT" ] || VOID="$VOID
  frames sent = ${SENT:-0} in ${SECS}s, under ${MINSENT} (2/s). A starved transmitter
  cannot be adopted, and it will lose to any peer that is transmitting normally."
# C. were we synchronised? Frames aimed with a bad phase land while the peer is elsewhere,
#    and "ignored us" is then indistinguishable from "never heard us".
[ "${ADOPTED:-false}" = "true" ] || VOID="$VOID
  adopted=${ADOPTED:-?}. Our frames were not aimed at the cluster's windows."
[ -n "${SPREAD:-}" ] && [ "$SPREAD" -lt 32768 ] || VOID="$VOID
  spread=${SPREAD:-?} us, not under half a slot (32768)."
# D. did our frames reach the air? The beacon's own counter is not evidence of that.
OURS=$(ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl stats $R.pcap 2>&1 | grep -c '$OURMAC'")
[ "${OURS:-0}" -gt 0 ] || VOID="$VOID
  our address does not appear in the capture: the frames never reached the air."

echo "  frames sent     ${SENT:-?}   (>= ${MINSENT:-?}, i.e. 2/s)"
echo "  adopted         ${ADOPTED:-?}   (true)"
echo "  spread          ${SPREAD:-?} us   (< 32768)"
echo "  master changes  ${CHANGES:-?}"
echo "  our frames on the air: ${OURS:-0} reference(s)"


# E. was a PEER even present? An empty room refuses everything, and run E3 spent eight
#    minutes proving that a garbage field is refused by nobody at all. This is the check
#    that was missing, and it is the difference between a result and a void.
PEERS=$(ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl stats $R.pcap 2>&1 | sed -n '/^senders:/,/^[a-z]/p' | grep -cvE '^senders:|$OURMAC|^[a-z]'")
[ "${PEERS:-0}" -ge 1 ] || VOID="$VOID
  no sender other than us appears in the capture. The room was empty, so nothing
  refused anything -- this is a void, not a REFUSE."
echo "  peers transmitting: ${PEERS:-0}   (>= 1)"

# F. if we were perturbing a field, did the perturbation actually reach the air? An encoder
#    that dropped the change makes a garbage run look exactly like a clean one.
if [ -n "$GARBAGE" ]; then
  echo "  --garbage $GARBAGE, as sent:"
  ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl tlv $R.pcap 24 $OURMAC 2>&1 | sed -n '3,8p'"
fi


# G. DID A PEER ENTER DURING THE CAPTURE? This is the one that matters for election, and
#    it was missed by eye three runs in a row. A settled cluster does not re-elect whatever
#    you advertise -- so a REFUSE from a room that was already settled is the known null
#    result, not evidence about anything you changed. Measured directly: run Z1b (byte 28
#    perturbed) and Z0ctl (nothing perturbed) both scored 0 in the same settled room,
#    minutes apart. The control is what stopped that becoming a finding.
#
#    An entry event looks like dots then letters in the timeline: the peer was off the air,
#    then arrived. `awdl timeline` prints one line per sender.
#    NOT "the line starts with dots" -- the first version tested that and scored the good
#    control as 0. A peer that was master, went away and came back reads `MMM...fff`, which
#    is the commonest entry shape of all. The test is a dot with presence somewhere AFTER it.
ENTRY=$(ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl timeline $R.pcap 2>&1 | grep -E '^[0-9a-f]{2}:' | grep -v '$OURMAC' | awk '{print \$2}' | grep -cE '[.][.]*[A-Za-z*]'")
[ "${ENTRY:-0}" -ge 1 ] || VOID="$VOID
  no peer ENTERED during the capture -- every peer was either present throughout or absent
  throughout. A settled cluster refuses correct frames as readily as garbage, so this is a
  void, not a REFUSE. Have the operator toggle AirDrop off and back on INSIDE the window."
echo "  peers that entered during the run: ${ENTRY:-0}   (>= 1 for an election test)"

echo
echo "=================== OUTCOME ==================="
ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl stats $R.pcap 2>&1 | grep -A10 'who names whom' | tail -9"
# awk, not bc: the Pi has no bc, and this runs there.
NAMED=$(ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && ./target/release/awdl stats $R.pcap 2>&1 | grep -E '\->  *$OURMAC' | awk '{n+=\$NF} END {print n+0}'")
NAMED=${NAMED:-0}

echo
if [ -n "$VOID" ]; then
  echo "VOID — no result. $VOID"
  exit 3
fi
echo "frames from a non-us sender naming us master: $NAMED  (>= 20 is ADOPT)"
if [ "$NAMED" -ge 20 ]; then echo "ADOPT"; else echo "REFUSE"; fi
