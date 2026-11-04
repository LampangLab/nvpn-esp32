#!/bin/bash
# Like mesh3.sh, but the "PC" node P is killed and restarted (same identity) after RESTART_AT seconds.
# Checks that the leaf notices the dead session and re-establishes it by itself.
set -u
cd "$(dirname "$0")"
ECHO=${ECHO:-interop-rs/target/release/echo}; [ -x "$ECHO" ] || ECHO=/home/claude/interop-rs/target/release/echo
SECS=${1:-120}; RESTART_AT=${RESTART_AT:-20}
rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SK_S=$(rnd); SK_P=$(rnd); SK_C=$(rnd)
TMP=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
$ECHO interop-rs/seed.yaml "$SK_S" > "$TMP/seed.log" 2>&1 & sleep 3
NPUB_S=$(awk '/^npub/{print $2; exit}' "$TMP/seed.log")
sed "s/@SEED_NPUB@/$NPUB_S/" interop-rs/p.yaml.in > "$TMP/p.yaml"
$ECHO "$TMP/p.yaml" "$SK_P" > "$TMP/p.log" 2>&1 & PPID_=$!
sleep 3; NPUB_P=$(awk '/^npub/{print $2; exit}' "$TMP/p.log"); sleep 4
START=$(date +%s)
( sleep "$RESTART_AT"; kill $PPID_; sleep 2; $ECHO "$TMP/p.yaml" "$SK_P" > "$TMP/p2.log" 2>&1 & echo "[$(( $(date +%s)-START ))s] P restarted" ) &
KEEP=1 ./tunnel_ping "$SK_C" "$NPUB_P" 127.0.0.1:2122 "$SECS" - "$NPUB_S" | while read -r l; do
  case "$l" in DELIVER*) echo "[$(( $(date +%s)-START ))s] reply";; replies*|RESULT*) echo "$l";; esac
done | awk '/reply$/{n++; last=$1; if(!first[$1])first[$1]=1; next} {print} END{print "last reply at " last}' | tail -5
