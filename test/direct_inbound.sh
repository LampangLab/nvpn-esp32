#!/bin/bash
# Direct (single-hop) regression: the Rust node is the upstream AND initiates the session towards the C node.
cd "$(dirname "$0")"
ECHO=${ECHO:-interop-rs/target/release/echo}; [ -x "$ECHO" ] || ECHO=/home/claude/interop-rs/target/release/echo
rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SK=$(rnd); SKC=$(rnd); TMP=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
$ECHO interop-rs/seed.yaml "$SK" > "$TMP/a.log" 2>&1 & A=$!; sleep 1.5
NP=$(awk '/^npub/{print $2;exit}' "$TMP/a.log"); kill $A; wait $A 2>/dev/null; sleep 1
set -- $(./tunnel_ping "$SKC" "$NP" 127.0.0.1:1 0 2>/dev/null | awk '/my ip/{print $3,$6}')
$ECHO interop-rs/seed.yaml "$SK" "$(./tunnel_ping --npub "$SKC")" "$2" "$1" > "$TMP/b.log" 2>&1 & sleep 1.5
./tunnel_ping "$SKC" "$NP" 127.0.0.1:2122 15 listen | tail -2
