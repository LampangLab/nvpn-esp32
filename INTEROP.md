# Interop notes (for implementers of other small FIPS / nostr-vpn clients)

Status as of the versions below. This is an independent port; nothing here is endorsed by the nostr-vpn or FIPS projects.

## Versions

| Item | Version |
|---|---|
| nostr-vpn desktop app (hardware tests) | 4.1.19, `fips_core` 0.4.110 |
| Reference node used in the host tests | `nvpn-fips-core` 0.4.107 and 0.4.110 (built from the crates) |
| Specification read | `mmalmi/fips` `docs/design/fips-wire-formats.md` ("Client role negotiation") and `fips-mesh-operation.md` ("Client-Only Operation"), tag `fips-core-v0.4.108` |
| Hardware | one Arduino-ESP32 board (library 0.3.0 for runs 1–3, 0.3.1 for run 4), public seed `fips2.iris.to` |
| Public seed (per the maintainer on nostr-vpn#157) | nvpn 4.1.17, FIPS core 0.4.96: no `ClientSupport` handler |

## Client-only role (implemented)

1. On link-up the leaf sends `ClientSupport` (0x53, no payload) before any tree announcement.
2. When the upstream's tree bootstrap has arrived, the leaf allows one announcement interval (2 s) for the upstream's `ClientSupport`/`ClientOnly`.
3. If it answers: the leaf sends `ClientOnly` (0x52, u64 LE declaration sequence) **instead of** `TreeAnnounce`, and a Bloom filter holding only its own identity. The sequence is taken from the tree-sequence counter (seeded from the upstream's unix timestamp), so it advances past any earlier router declaration. It is repeated at the normal announcement cadence with the same sequence (the reference implementation accepts an equal sequence from a node that is already a client).
4. If it does not answer within the interval, the upstream has no leaf support (per the maintainer: nvpn 4.1.17 / FIPS core 0.4.96 has no `ClientSupport` handler, so silence is expected; 0.4.110 answers). The leaf cannot forward transit traffic, so it must not advertise itself as a router: it enters **role 3 (waiting)**, traces `upstream lacks leaf support`, announces nothing, and retries `ClientSupport` every 30 s. A late answer switches it to the client role. The old behaviour (fallback to `TreeAnnounce`) exists only as an opt-in, `fips_t.allow_router_fallback = 1`, for tests of legacy interop.
5. The leaf never forwards, never offers itself as root or parent, answers only lookups for its own identity, and keeps its own coordinates ([self] + upstream ancestry) for lookup replies and sessions.

Tests (`test/client_role.sh`, loopback, real `nvpn-fips-core` nodes; all pass on 0.4.107 and 0.4.110): default → client-only + ping through the seed; negotiation disabled → TreeAnnounce + ping; upstream answer ignored → role 3, no TreeAnnounce sent; same with `allow_router_fallback` → TreeAnnounce + ping; peer-initiated session towards the client-only leaf.
Not tested: a genuinely legacy (pre-0.4.101) node, real hardware against `fips1/2.iris.to` (to be reported separately).

## Rekeys

The leaf answers peer-initiated FSP rekeys (SessionSetup → msg3 → pending epoch; cutover on the first authenticated frame with the other K bit; previous epoch drained for a fixed window). It **never initiates** a rekey, and it does **not** answer a peer-initiated FMP link rekey (an FMP `msg1` arriving on an established link is only counted and traced). Whether the public seeds ever start FMP rekeys towards a leaf is exactly what the trace below should show.

### Trace format (Arduino examples)

Every event prints one line; no keys or payloads are logged:

```
RK #<n> t=<sec.ms>s link_tx=<FMP frames sent> link_rx=<authenticated frames received> <event> arg=<x>
```

Events: `link-up`, `link-down`, `FMP msg1 rx` (peer starts a *link* rekey), `FMP K-flip` (link key epoch changed), `FSP SessionSetup rx`, `FSP msg3: new session`, `FSP msg3: REKEY` (pending epoch stored), `FSP cutover` (pending epoch promoted), `FSP dead-peer reset`, and role events (`ClientSupport tx/rx`, `ClientOnly tx`, `TreeAnnounce tx`, `upstream lacks leaf support`, `fallback`). `RK status` every 30 s prints the role. The existing `DG …` line carries the counters (`aead`, `prom`, `deadreset`).

To attribute rekeys, compare the board's `RK` lines with the PC's `daemon.log` for the same wall-clock window (the board has no real-time clock in the trace; note the uptime at a known event such as `link-up`).

## Findings from the first hardware trace (board `jame` Wi-Fi, PC app 4.1.19 / core 0.4.110, seed `fips2.iris.to`, 15 min)

- `fips2.iris.to` did **not** answer `ClientSupport`; the leaf fell back to `TreeAnnounce` after one interval (`role=2` for the whole run; this was the pre-0.3.1 behaviour). The maintainer later confirmed that seed runs nvpn 4.1.17 / FIPS core 0.4.96, which has no `ClientSupport` handler. Since then the leaf reports the missing support and waits instead (role 3).
- No FMP event at all in 929 s: no peer `msg1`, no K-flip. Every rekey was an FSP rekey initiated by the PC, 15 of them, one every 59.9–60.0 s. They match the PC's `Unacknowledged session traffic exceeded recovery window; starting recovery rekey` lines 1:1 (not the configured timer).
- Cause (from reading `recover_unresponsive_sessions` and `has_unacknowledged_outbound_from` in core 0.4.110): with receiver reports enabled, the PC treats only an advancing session `ReceiverReport` (0x12), or a validated direct path, as delivery feedback; our leaf sent none, so any PC data unreported for 5 s triggered a recovery rekey. The leaf now sends a session `ReceiverReport` (counters, echoed timestamp, dwell; at most one per second per session, only after data arrived). The 66-byte body round-trips through the real `SessionReceiverReport` decoder (`test/rr_vector.c`), and host sessions against 0.4.107/0.4.110 keep working. Hardware results are in the run table below.
- Second run with the `ReceiverReport` (898 s): the PC's recovery rekeys of the board fell from one per minute (15 in 15 min) to 4 in about 15 min on the PC log, and the board saw 1 pending-epoch rekey and 1 dead-peer reset instead of 15 rekeys. Some recovery rekeys remain; cause not yet known.
- The 91-byte "rejected" messages (about one per 10 s) are nostr-vpn application control frames sharing the message type used for IPv4: `NVPN-FIPS-CTRL\0` + `{"v":1,"frame":{"kind":"ping","network_id":"…","sent_at":N}}` (`fips_control.rs`, `FipsControlFrame::Ping`). The app treats the `Pong` as presence. The leaf now answers `Ping` with `Pong` (same `network_id` and `sent_at`, `replied_at` = unix time derived from the upstream's tree timestamps, monotonic). Verified on the host against a real core node that sends the same frame (`MODE=in` in `test/mesh3.sh`: 19 pings, 19 pongs), and on hardware: the desktop app reports the board `reachable: true` with a fresh `last_fips_control_seen_at`, and the board's `ctrl_ping` and `pong` counters stay equal (164/164 after ~27 min). Other frame kinds are counted and ignored.

## Hardware runs

Same board and network for all runs (board on Wi-Fi `jame`, PC on a different network, seed `fips2.iris.to`, PC app 4.1.19 / core 0.4.110). Times are board uptime; PC lines come from the PC `daemon.log` (UTC) for the same window.

| Run | Library | Duration | Board role | Recovery rekeys of the board on the PC | Board-side rekey events | Reachability |
|---|---|---|---|---|---|---|
| 1 | 0.2.x, no `ReceiverReport` | ~929 s | 2 (TreeAnnounce) | 15 (one per ~60 s) | no FMP events | ping ok |
| 2 | 0.3.0, `ReceiverReport` | ~898 s | 2 | 4 | 1 pending-epoch rekey, 1 dead-peer reset | ping ok |
| 3 | 0.3.0 | ~14 min | 2 | 0 | 0 | ping ok |
| 4 | 0.3.1, role 3 | ~1650 s (27 min) | **3 (waiting, nothing advertised)** | **1, at the moment of the board's boot; 0 afterwards** | 0 (`aead=0 deadreset=0 prom=0`) | ping 20/20, avg 594 ms (544–696); app `reachable: true`, srtt ~550–765 ms |

Run 4 details: 41 `RK` lines, all `ClientSupport tx` (every 30 s); no `TreeAnnounce tx`; `ctrl_ping` = `pong`; UDP echo and TCP/HTTP from the board to a PC service over the mesh passed while the service was running (rtt 515–700 ms). The PC log also contains `NAT traversal failed ... cooldown_secs=1800` for the board (the board does no Nostr traversal, so traffic stays on the public-seed path) and `recovery rekey` lines for *another* peer's session; neither concerns the board's data path. The single recovery rekey at the board's boot is attributed (inferred from timestamps, not observed directly) to the PC still holding the session of the previous firmware instance.

Takeaway for implementers: a leaf that cannot forward does not need to advertise a tree position to be reachable through a seed that already has a link to it, and answering `Ping` and sending session `ReceiverReport`s were enough to remove the periodic recovery rekeys in these runs. Not covered: other seeds or topologies, long runs, packet loss.

## Open items

- `JoinRequest` / `JoinRoster` / `JoinRosterAck` (stateful, over FIPS-TCP service port 7370; validate request binding, roster signature, admin/member identity and freshness, persist, then ack with the exact roster event id) — not implemented, so the app may show "waiting for this device to confirm".
- Phone-to-board across genuinely separate networks, reconnect behaviour (Wi-Fi drop, board reboot) and packet loss during rekey on hardware — not yet measured.
- A seed running core 0.4.110 or newer, to observe the client-only path on hardware (so far verified only against local `nvpn-fips-core` nodes).
- Initiating rekeys / enforcing our own key-lifetime policy; MMP `SenderReport`s and link-layer reports.
