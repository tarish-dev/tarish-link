#!/bin/bash
# ONE FORMING-ROOM TRIAL — the positive control, and the only condition in which adoption
# has ever been observed.
#
# The difference from compete-trial.sh is the ROOM, and it is the hard part. A forming cell
# needs the peers to arrive while we are already transmitting, and two iPhones re-form a
# cluster in under ten seconds -- less than this script's own startup. So the condition is
# established DURING the capture, on a cue, and never before it. Four consecutive runs died
# on exactly that. PROTOCOL.md rules 7 and 9.
#
#   VOID    a precondition failed, including "the peers were never forming"
#   ADOPT   >= 20 frames from a non-us sender naming our address as master
#   REFUSE  the preconditions held and nobody adopted us
set -u
PI=${PI:-pi@raspberrypi.local}
MON=${MON:-mon0}
MANAGED=${MANAGED:-wlx00c0cab0604c}
OURMAC=${OURMAC:-00:c0:ca:b0:60:4c}
CHAN=${CHAN:-149}
METRIC=${METRIC:-600}
SECS=${SECS:-170}
CAPS=${CAPS:-150}
LABEL=${LABEL:-fh}
FLAGS=${FLAGS:-}

R=/tmp/ft_$LABEL

echo "### 1. checking the room is EMPTY before we start"
ssh -o ConnectTimeout=10 "$PI" "
cd ~/tarish-libawdl
sudo killall awdl tcpdump 2>/dev/null; sudo ip link del awdl0 2>/dev/null; sleep 1
sudo timeout 12 tcpdump -i $MON -w $R.before.pcap -s0 2>/dev/null
./target/release/awdl stats $R.before.pcap 2>&1 | grep -E 'AWDL action|no AWDL' | head -2
./target/release/awdl stats $R.before.pcap 2>&1 | grep -A6 'senders:' | head -7
"

echo
echo "### 2. starting the beacon at metric $METRIC $FLAGS"
#
# HARNESS BUG 6. `ssh host 'cmd &'` does NOT return while the background child still holds
# the session's stdout or stderr, so a call meant to START something and hand control back
# blocks for the whole run instead. It cost a forming trial: the cue to switch the phones on
# arrived two minutes after the capture had opened, and the capture contained nothing but our
# own 426 frames.
#
# nohup plus all three descriptors redirected is what makes ssh let go. Same reason as
# harness bug 3, different disguise.
ssh -o ConnectTimeout=10 "$PI" "
cd ~/tarish-libawdl
nohup sudo ./target/release/awdl beacon $MANAGED $MON $CHAN $SECS 2 --metric $METRIC --tenure 99999 $FLAGS > $R.log 2>&1 < /dev/null &
for i in \$(seq 1 15); do ip link show $MON >/dev/null 2>&1 && break; sleep 1; done
sleep 4
nohup sudo timeout $CAPS tcpdump -i $MON -w $R.pcap -s0 > /dev/null 2>&1 < /dev/null &
sleep 2
echo \"beacon:\$(ps -eo comm | grep -c '^awdl\$') tcpdump:\$(ps -eo comm | grep -c '^tcpdump\$')\"
"
echo
echo "#############################################################"
echo "###  CAPTURE IS OPEN NOW — TURN AIRDROP ON, BOTH PHONES    ###"
echo "###  (they must JOIN during the window, not before it)     ###"
echo "#############################################################"
echo
echo "waiting for the window to close ($CAPS s)..."
while ssh -o ConnectTimeout=10 "$PI" "ps -eo comm | grep -q '^tcpdump$'" 2>/dev/null; do sleep 5; done
sleep 14

fetch() { ssh -o ConnectTimeout=10 "$PI" "cd ~/tarish-libawdl && $1" 2>/dev/null; }

echo "=================== OUR RUN ==================="
LOG=$(fetch "cat $R.log")
echo "$LOG" | grep -E '^sent|^cluster|^adopted by'

SENT=$(echo "$LOG" | grep -oE '^sent [0-9]+ MIF, [0-9]+ PSF' | grep -oE '[0-9]+' | awk '{n+=$1} END {print n+0}')
LIVE=$(echo "$LOG" | grep -oE 'adopted by [0-9]+ peer' | grep -oE '[0-9]+')

echo
echo "=================== DID THE PEERS FORM? (rule 7) ==================="
echo "silent at the start then arriving is '..*' — talking in bucket 1 is SETTLED, not forming"
fetch "./target/release/awdl timeline $R.pcap 2>&1 | sed -n '3,14p'"

echo
echo "=================== VALIDITY ==================="
VOID=""
# RATE, not a flat count. 40 frames passed this check for a 420-second run that was
# out-transmitted 2884 to 151 and voided; the healthy rate is one frame per advertised
# window, three windows per 1.049 s cycle, so ~2.8/s. Anything under 2/s is starved.
MINSENT=$(awk -v s="$SECS" 'BEGIN {print int(s * 2)}')
[ "${SENT:-0}" -ge "$MINSENT" ] || VOID="$VOID
  frames sent = ${SENT:-0} in ${SECS}s, under ${MINSENT} (2/s). A starved transmitter
  cannot be adopted, and it will lose to any peer that is transmitting normally."
OURS=$(fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -c '$OURMAC'")
[ "${OURS:-0}" -gt 0 ] || VOID="$VOID
  our address is absent from the capture: the frames never reached the air."
PEERS=$(fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -A8 'senders:' | grep -cE '^  [0-9a-f]{2}:'")
[ "${PEERS:-0}" -ge 2 ] || VOID="$VOID
  only ${PEERS:-0} sender(s) in the capture: no peer ever showed up to adopt anything."
echo "  frames sent            ${SENT:-?}   (>= ${MINSENT:-?}, i.e. 2/s)"
echo "  our frames on the air  ${OURS:-0} reference(s)"
echo "  senders present        ${PEERS:-0}   (>= 2, us plus a peer)"
echo "  live adoption count    ${LIVE:-0} peer(s)   <- from the beacon itself"

echo
echo "=================== OUTCOME ==================="
fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -A10 'who names whom' | tail -9"
NAMED=$(fetch "./target/release/awdl stats $R.pcap 2>&1 | grep -E '\->  *$OURMAC' | awk '{n+=\$NF} END {print n+0}'")
NAMED=${NAMED:-0}
echo
if [ -n "$VOID" ]; then echo "VOID — no result.$VOID"; exit 3; fi
echo "frames from a non-us sender naming us master: $NAMED  (>= 20 is ADOPT)"
echo
echo "NOTE: the timeline above decides whether this was a FORMING room. If the peers were"
echo "talking in bucket 1 this is a settled cell however it was set up, and the outcome"
echo "belongs with compete-trial.sh's numbers rather than here."
if [ "$NAMED" -ge 20 ]; then echo "ADOPT"; else echo "REFUSE"; fi
