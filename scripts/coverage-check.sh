#!/bin/bash
# The coverage ratchet. Fails if the parser understands less of the corpus than it did.
#
# Exit codes follow the convention the integration scripts use:
#   0  the floor held
#   2  the baseline file is missing or unreadable
#   3  a floor fell -- something changed and a human must decide what
#
# A floor falls for exactly two reasons and they want different answers:
#
#   the parser regressed          -> fix the parser
#   a new capture carries a shape
#   we cannot classify            -> that is a FINDING, write it down, then decide
#
# Do not reach for --update-baseline to make this quiet. Regenerating the baseline is how
# a real gap becomes the new normal, and the number stops meaning anything the first time
# it happens.
set -eu
cd "$(dirname "$0")/.."

BIN=./target/release/awdl
BASE=docs/coverage-floor.txt

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 2; }

# captures/*.pcap includes three BLE files that are not AWDL; the tool skips them on
# stderr rather than failing, which is why stderr is dropped here and not the exit code.
"$BIN" coverage captures/*.pcap --baseline "$BASE" 2>/dev/null
