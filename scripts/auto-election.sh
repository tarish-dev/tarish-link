#!/bin/bash
# UNATTENDED ELECTION TRIALS. Alternates two arms and scores each one against the same
# pre-registered gate the interactive harness uses.
#
#   control    --metric 600                    (one constant metric, what we have always sent)
#   floor      --metric 600 --metric-floor 3    (65 first, then step — finding 77's shape)
#   windows    --metric 600 --windows 8         (occupy 8 slots of 16, not 3 — finding 75/76)
#
# Three arms because there are two live candidates, not one. We advertise 3 slots of 16 where
# Apple advertises 4 and widens to 6 and 8, and a master absent from most of the cycle is a
# poor timing anchor whatever metric it claims. Trial E's lone historical takeover was made
# while accidentally occupying six windows.
#
# The point is n. Finding 78 rests on ONE valid floor run against two controls, and finding
# 75 measured spontaneous takeovers at roughly one attempt in three — so a single success
# proves nothing and only alternation over many trials separates the arms.
#
# Every trial is scored VOID rather than counted when a precondition fails. The three that
# actually bite, all observed in one evening:
#   - empty room: the phones idle out of AWDL, especially once iOS reverts to Contacts Only
#   - entry events: a peer leaving and rejoining, INCLUDING an AWDL MAC rotation, which is
#     how run FL2 scored an ADOPT that meant nothing
#   - our own transmitter starved
#
# Results append to $OUT/results.tsv, one line per trial, with the reason for every void.
set -u
MON=${MON:-mon0}
MANAGED=${MANAGED:-wlx00c0cab0604c}
OURMAC=${OURMAC:-00:c0:ca:b0:60:4c}
CHAN=${CHAN:-149}
METRIC=${METRIC:-600}
TRIALS=${TRIALS:-40}
SECS=${SECS:-240}
CAPS=${CAPS:-210}
SETTLE=${SETTLE:-75}
OUT=${OUT:-/tmp/auto}
BIN=./target/release/awdl

mkdir -p "$OUT"
[ -f "$OUT/results.tsv" ] || printf 'trial\tarm\tpeers\tentry\tsent\tnamed_us\tverdict\tincumbent\tinc_metric\tnote\n' > "$OUT/results.tsv"

for i in $(seq 1 "$TRIALS"); do
  case $((i % 3)) in
    1) ARM=control; FLAG="" ;;
    2) ARM=floor;   FLAG="--metric-floor 3" ;;
    0) ARM=windows; FLAG="--windows 8" ;;
  esac
  R="$OUT/t${i}_${ARM}"
  sudo killall awdl tcpdump 2>/dev/null
  sleep "$SETTLE"
  sudo rm -f "$R".*

  # PRE: the room must contain a settled peer before we transmit into it.
  sudo timeout 20 tcpdump -i "$MON" -w "$R.pre.pcap" -s0 2>/dev/null
  PEERS=$($BIN stats "$R.pre.pcap" 2>&1 | sed -n '/^senders:/,/^[a-z]/p' | grep -cvE "^senders:|$OURMAC|^[a-z]")
  INC=$($BIN stats "$R.pre.pcap" 2>&1 | grep -E '\->  \(itself\)' | sort -k4 -rn | head -1 | awk '{print $1}')
  INCM=$($BIN read "$R.pre.pcap" 2>/dev/null | awk -v inc="$INC" '
    /^#[0-9]+ / { for(j=1;j<=NF;j++) if($j=="->"){s=$(j-1); break} }
    /v2 distance/ { for(j=1;j<=NF;j++) if($j=="self") m=$(j+1); if(s==inc){split(m,a,"#"); print a[1]; exit} }')
  if [ "${PEERS:-0}" -lt 1 ]; then
    printf '%s\t%s\t0\t-\t-\t-\tVOID\t-\t-\tempty room before the run\n' "$i" "$ARM" >> "$OUT/results.tsv"
    continue
  fi

  nohup sudo $BIN beacon "$MANAGED" "$MON" "$CHAN" "$SECS" 2 --follow --metric "$METRIC" --tenure 99999 $FLAG > "$R.log" 2>&1 < /dev/null &
  sleep 6
  sudo timeout "$CAPS" tcpdump -i "$MON" -w "$R.pcap" -s0 2>/dev/null
  sleep 6
  sudo killall awdl 2>/dev/null

  SENT=$(grep -oE '^sent [0-9]+ MIF, [0-9]+ PSF' "$R.log" 2>/dev/null | grep -oE '[0-9]+' | awk '{n+=$1} END {print n+0}')
  ENTRY=$($BIN timeline "$R.pcap" 2>&1 | grep -E '^[0-9a-f]{2}:' | grep -v "$OURMAC" | awk '{print $2}' | grep -cE '[.][.]*[A-Za-z*]')
  NAMED=$($BIN stats "$R.pcap" 2>&1 | grep -E "\->  *$OURMAC" | awk '{n+=$NF} END {print n+0}')
  RPEERS=$($BIN stats "$R.pcap" 2>&1 | sed -n '/^senders:/,/^[a-z]/p' | grep -cvE "^senders:|$OURMAC|^[a-z]")

  V=ADOPT; NOTE=""
  [ "${NAMED:-0}" -ge 20 ] || V=REFUSE
  if [ "${RPEERS:-0}" -lt 1 ]; then V=VOID; NOTE="room emptied during the run"; fi
  if [ "${ENTRY:-0}" -ge 1 ]; then V=VOID; NOTE="peer entered or rotated MAC — not a settled test"; fi
  if [ "${SENT:-0}" -lt $((SECS * 2)) ]; then V=VOID; NOTE="transmitter starved: $SENT frames"; fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$i" "$ARM" "${RPEERS:-0}" "${ENTRY:-0}" "${SENT:-0}" "${NAMED:-0}" "$V" "${INC:--}" "${INCM:--}" "$NOTE" >> "$OUT/results.tsv"

  # Keep only captures worth re-reading; a night of 200 MB pcaps helps nobody.
  if [ "$V" = ADOPT ]; then gzip -f "$R.pcap" 2>/dev/null; else rm -f "$R.pcap"; fi
  rm -f "$R.pre.pcap"
done
sudo killall awdl tcpdump 2>/dev/null
echo "DONE $(date -u +%H:%M)" >> "$OUT/results.tsv"
