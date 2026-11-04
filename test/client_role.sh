#!/bin/bash
# Client-only role negotiation against the real nostr-vpn FIPS core (needs test/interop-rs built).
#  1. default            -> upstream answers ClientSupport  => role client-only, ping through the seed works
#  2. NVPN_NO_CLIENT=1   -> negotiation disabled           => TreeAnnounce, ping works
#  3. NVPN_NO_CLIENT=2   -> upstream "never answers"       => role waiting: no TreeAnnounce is ever sent (the seed may still route to us over the direct link)
#  4. NVPN_NO_CLIENT=3   -> same + allow_router_fallback   => legacy TreeAnnounce fallback after one interval, ping works
cd "$(dirname "$0")"; fail=0
for case in "0|client-only|1" "1|fallback|1" "2|waiting|x" "3|fallback|1"; do
  IFS='|' read m want wping <<< "$case"
  out=$(KEEP=1 NVPN_NO_CLIENT=$m timeout 90 ./mesh3.sh 8 2>&1)
  ps -eo pid,cmd | grep "release/echo" | grep -v grep | awk '{print $1}' | xargs -r kill 2>/dev/null; sleep 1
  role=$(echo "$out" | awk '/^ROLE:/{print $2}'); rc=$(echo "$out" | grep -c "RESULT: PING OK")
  tx=$(echo "$out" | grep -c "kind=14 ")                       # TreeAnnounce tx events
  if [ "$want" = waiting ] && [ "$role" = waiting ] && [ "$tx" = 0 ]; then echo "PASS NVPN_NO_CLIENT=$m role=$role, no TreeAnnounce sent (ping_ok=$rc: the seed still routes from its direct link)"
  elif [ "$wping" != x ] && [ "$role" = "$want" ] && [ "$rc" = "$wping" ]; then echo "PASS NVPN_NO_CLIENT=$m role=$role ping_ok=$rc"; else echo "FAIL NVPN_NO_CLIENT=$m role=$role (want $want) ping_ok=$rc"; fail=1; fi
done
# 5. inbound: a Rust peer opens the session towards the client-only leaf through the seed (30 s: the peer retries)
out=$(MODE=in timeout 90 ./mesh3.sh 30 2>&1); ps -eo pid,cmd | grep "release/echo" | grep -v grep | awk '{print $1}' | xargs -r kill 2>/dev/null
if echo "$out" | grep -q "INBOUND OK" && echo "$out" | grep -q "^ROLE: client-only"; then echo "PASS inbound to client-only leaf"; else echo "FAIL inbound to client-only leaf"; fail=1; fi
exit $fail
