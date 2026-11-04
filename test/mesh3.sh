#!/bin/bash
# Three-node mesh test with the real nostr-vpn FIPS core:
#   seed (Rust, public-seed stand-in) <-- P (Rust, "the PC": echoes ICMP)   and   C (this C library, a leaf) -> seed
# C pings P *through the seed*: lookup, SessionSetup routed over two hops, Noise XK end to end, EndpointData.
# usage: mesh3.sh [secs]      (needs test/interop-rs built:  cd interop-rs && cargo build --release)
set -u
cd "$(dirname "$0")"
ECHO=${ECHO:-interop-rs/target/release/echo}
[ -x "$ECHO" ] || ECHO=/home/claude/interop-rs/target/release/echo
SECS=${1:-30}
rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SK_S=$(rnd); SK_P=$(rnd); SK_C=$(rnd)
TMP=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
$ECHO interop-rs/seed.yaml "$SK_S" > "$TMP/seed.log" 2>&1 &
sleep 3
NPUB_S=$(awk '/^npub/{print $2; exit}' "$TMP/seed.log")
sed "s/@SEED_NPUB@/$NPUB_S/" interop-rs/p.yaml.in > "$TMP/p.yaml"
$ECHO "$TMP/p.yaml" "$SK_P" > "$TMP/p.log" 2>&1 &
sleep 3
NPUB_P=$(awk '/^npub/{print $2; exit}' "$TMP/p.log")
echo "seed $NPUB_S"; echo "P    $NPUB_P"
sleep ${WARM:-4}                      # let P link to the seed and the tree / bloom filters converge
if [ "${MODE:-out}" = "in" ]; then
  # inbound: P starts the session towards C (C only listens); P needs C's mesh IP, derived from the shared network id "testnet"
  pkill -f "$TMP/p.yaml" 2>/dev/null; sleep 0.5
  NPUB_C=$(./tunnel_ping --npub "$SK_C")
  IPS=$(./tunnel_ping "$SK_C" "$NPUB_P" 127.0.0.1:1 0 2>/dev/null | awk '/my ip/{print $3, $6}')
  set -- $IPS
  $ECHO "$TMP/p.yaml" "$SK_P" "$NPUB_C" "$2" "$1" > "$TMP/p.log" 2>&1 &
  ./tunnel_ping "$SK_C" "$NPUB_P" 127.0.0.1:2122 "$SECS" listen "$NPUB_S"
else
  ./tunnel_ping "$SK_C" "$NPUB_P" 127.0.0.1:2122 "$SECS" - "$NPUB_S"
fi
RC=$?
echo "--- P log (tail)"; grep -E "CTRL" "$TMP/p.log" | tail -n 4; tail -n 4 "$TMP/p.log"
exit $RC
