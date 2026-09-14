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

R=/tmp/ct_$LABEL
ssh -o ConnectTimeout=10 "$PI" "
set -u
cd ~/tarish-libawdl
sudo killall awdl tcpdump 2>/dev/null; sleep 1

# BEFORE: is the room a settled cluster at all? A trial against an empty or churning room
# measures nothing, and both look like a clean refusal afterwards.
sudo timeout 12 tcpdump -i $MON -w $R.before.pcap -s0 2>/dev/null
./target/release/awdl stats $R.before.pcap 2>&1 | grep -A8 'who names whom' > $R.before.txt
./target/release/awdl timeline $R.before.pcap 2>&1 | sed -n '3,12p' > $R.timeline.txt

(sudo ./target/release/awdl beacon $MANAGED $MON $CHAN $SECS 2 --follow --metric $METRIC --tenure 99999 > $R.log 2>&1 &)
for i in \$(seq 1 15); do ip link show $MON >/dev/null 2>&1 && break; sleep 1; done
sleep 4
sudo timeout $CAPS tcpdump -i $MON -w $R.pcap -s0 2>/dev/null
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
