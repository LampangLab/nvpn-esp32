[README.md](https://github.com/user-attachments/files/34397160/README.md)
# nvpn-esp32

**Put an ESP32 on a private [nostr-vpn](https://github.com/mmalmi/nostr-vpn) mesh — from any Wi-Fi, behind any NAT, with no server of your own.**

`nvpn-esp32` is a small C library (no heap, no OS assumptions) that lets an ESP32 join a nostr-vpn network as a leaf node. The board gets a virtual LAN address (`10.44.x.y`), and other members (a PC, a phone, other boards) can ping it and open TCP/UDP connections to it — and the board to them — through the public FIPS seed nodes, even when both sit behind CGNAT or a router you cannot configure.

An optional second layer lets *anyone with a web page* read a board's status and send it commands through a public **Nostr** relay — no app to install, no PC left running.

[ไทย / Thai README](README.th.md) · Repository: <https://github.com/LampangLab/nvpn-esp32>

> **Unofficial.** This project is an independent port. It is not affiliated with, endorsed by, or supported by the nostr-vpn, FIPS, Nostr, or iris.to projects. See [Credits](#credits-and-license).

## Why

Plain Wi-Fi gives you a LAN, not a network you can reach from outside. MQTT brokers, port-forwarding, VPS tunnels and paid IoT clouds all work, but each needs a server you run or pay for, or a router you control. nostr-vpn already solves the hard part (identity, signed membership, NAT traversal through public relays); this library brings that to microcontrollers.

```
 phone / PC (nostr-vpn app) ──┐                          ┌── ESP32 (nvpn-esp32)
                              ├── public FIPS seed ──────┤        nv0 = 10.44.x.y
 another ESP32 ───────────────┘   (outbound UDP only)    └── ordinary lwIP sockets
        end-to-end encrypted sessions (Noise XK); seeds only see ciphertext
```

## What it does

| Layer | What you get |
|---|---|
| **Control plane** | Nostr identity (BIP-340 Schnorr, `npub`), signed rosters (kind 30388) verified against a trusted admin, mesh-IP derivation identical to nostr-vpn, per-packet admission checks, MagicDNS answers |
| **FIPS data plane** | Noise IK link to one upstream node, mesh participation as a **client-only** leaf (`ClientSupport`/`ClientOnly` negotiation, an upstream that does not answer is reported and the leaf waits silently (it never advertises itself as a router; the old `TreeAnnounce` fallback is opt-in via `allow_router_fallback`); own-identity Bloom filter, coordinate lookup), end-to-end Noise XK sessions over several hops, EndpointData carrying raw IPv4, handling of peer-initiated rekeys |
| **Virtual LAN** | An lwIP interface `nv0` on Arduino-ESP32: use `WiFiClient`, `WiFiUDP`, `WebServer`, MQTT, … to mesh IPs as if they were on your LAN |
| **Nostr control layer** (optional) | Status and commands through a public Nostr relay, with a single-file web UI — see [docs/NOSTR.md](docs/NOSTR.md) |

Design: sans-IO. You supply the clock and send/receive callbacks; the core never allocates. libsecp256k1 (schnorrsig, extrakeys, ecdh) is vendored with a small precomputed table.

## Status — what is actually verified

Be realistic about maturity: this is early software, written against the wire protocol of nostr-vpn / FIPS `0.4.x`, and has not been audited.

**Verified on real hardware** (an Arduino-ESP32 board, home Wi-Fi, Windows PC running the nostr-vpn app 4.1.19 / fips-core 0.4.110):
- Link to a FIPS node on the LAN; ping both ways; UDP echo and TCP/HTTP from the board to the PC.
- Link to the **public seed `fips2.iris.to`** and communication with the PC through it: a ~30-minute run reached 114/123 UDP echo and 117/123 TCP/HTTP round-trips (≈7 % of probes failed; typical round trip 0.5–0.8 s). The PC's app rekeyed the session about once a minute during this run with no decryption errors on the board.
- 12/12 on-device crypto self-test.

**Verified on a development host only** (loopback, nodes built from the same `nvpn-fips-core 0.4.107` crate nostr-vpn uses): multi-hop leaf → seed → peer pings, inbound sessions through a seed, recovery after a peer restart, direct-path regression; the client-only role negotiation, its no-answer behaviour (role 3, nothing advertised) and an inbound session to the client-only leaf (`test/client_role.sh`, also against `nvpn-fips-core 0.4.110`); 1,215 unit/reference checks (expected values generated from the original Rust code), clean under ASan/UBSan.

**Not verified:** the phone app; two networks that are actually different (in the hardware run above the board and PC shared one Wi-Fi, although traffic went through the seed); ESP-IDF builds of the lwIP netif and IDF examples (only syntax-checked); long-term stability beyond ~30 minutes; other ESP32 variants; public relays other than the tests above; the Nostr layer on hardware (it is tested against nostr-tools, a mock relay and a host-compiled copy of the sketch, not a real relay).

**Known gaps:** leaf only (no forwarding for other nodes; it negotiates the FIPS client-only role, see [docs/INTEROP.md](docs/INTEROP.md)); does not initiate rekeys itself; MMP: only session `ReceiverReport`s are sent (no `SenderReport`s, no link-layer reports); answers only `Ping` control frames (with `Pong`), no join/ack frames (the nostr-vpn app may show "waiting for this device to confirm" although traffic works); no hole punching (traffic goes through the upstream); IPv4 inside `10.44.0.0/16` only; RAM use not yet measured or optimised.

## Quick start (Arduino IDE)

1. Download **`nvpn-esp32-arduino.zip`** from the [Releases page](../../releases) of this repository (do **not** use GitHub's *Download ZIP* of the repository: that is the full source tree, which Arduino IDE cannot install as a library). In Arduino IDE: *Sketch → Include Library → Add .ZIP Library* and select that file, then restart the IDE. If you installed an older version, delete the old `nvpn-esp32` folder under `Documents/Arduino/libraries/` first.
   (To build the zip yourself from a clone: `tools/make_arduino.sh out && (cd out && zip -r nvpn-esp32-arduino.zip nvpn-esp32)`; needs bash.)
2. Open *File → Examples → nvpn-esp32 → VirtualLan* (or `FipsLeaf` for the bare data plane; in a clone the same sketches are in `examples/arduino/`). Set your Wi-Fi, the admin's `npub`, and paste the signed roster JSON (`tools/extract_roster.py` helps).
3. Upload. The Serial monitor (115200) prints `this device: npub1…`. Add that `npub` to your network on the admin machine:
   ```sh
   nvpn add-device --device npub1… --publish && nvpn reload
   ```
   then paste the new roster into the sketch and upload again.
4. Ping the board's mesh IP from another member. `tools/mesh_ip.py` computes any member's IP from its key.

By default the sketch uses the public seed nodes the nostr-vpn app itself uses (`fips1.iris.to` / `fips2.iris.to`, port 51820). The nostr-vpn maintainer has said that small ESP32/MCU devices are welcome to use them and there is no need to run your own seed just because a device is constrained ([nostr-vpn#157](https://github.com/mmalmi/nostr-vpn/issues/157)). They are still third-party servers with no guarantee of service, so do not rely on them for anything critical; run your own `fips` node and point `UP_HOST` / `UP_PUBKEY` at it if you need that.

The Arduino examples print `RK …` trace lines (rekey / role events with timestamps and packet counts, no keys or payloads); see [docs/INTEROP.md](docs/INTEROP.md).

Step-by-step test guide (Windows PC + phone, in Thai): [docs/TESTING.md](docs/TESTING.md).

## Repository map

| Path | Contents |
|---|---|
| `include/`, `src/` | Public headers and implementation (`nvpn.h`, `fips.h`, `nvpn_tunnel.h`, `nvpn_netif.h`; control plane, FIPS link/session/mesh, tunnel) |
| `port/` | lwIP netif glue for ESP-IDF / Arduino-ESP32 |
| `third_party/secp256k1/` | Vendored libsecp256k1 (MIT) |
| `examples/arduino/` | `VirtualLan`, `FipsLeaf`, `SelfTest`, `NostrBoard` sketches |
| `examples/esp-idf-*`, `examples/host-udp/` | ESP-IDF examples and a Linux UDP client |
| `web/index.html` | Single-file web UI for the Nostr control layer |
| `tools/` | Arduino packaging, roster extraction, mesh-IP calculator, PC-side echo/check scripts |
| `test/` | Host test suite, interop scripts against real Rust nodes (`test/interop-rs`), Nostr-layer tests (`test/nostr`) |
| `docs/` | `TESTING.md` (Thai), `NOSTR.md` |

Run the host tests: `cd test && make test` (and `make asan`).

## Security notes

- The secret key is stored in plain NVS by the examples. Enable ESP32 flash encryption and NVS encryption for anything that matters.
- Mesh traffic is end-to-end encrypted (Noise), and membership is controlled by an admin-signed roster, but the library has had **no security audit**.
- The Nostr control layer signs but does **not encrypt** messages, and the sketch does not verify the relay's TLS certificate (a man in the middle can block traffic but cannot forge commands). Do not put secrets in it, and keep `CONTROLLERS[]` tight. Details in [docs/NOSTR.md](docs/NOSTR.md).
- Do not use this for safety-critical control.

## Contributing

Issues and pull requests are welcome, especially:
- test reports from other boards (ESP32-S3, -C3, …) and other networks, including two truly separate ones;
- an ESP-IDF build and hardware run of the lwIP netif;
- behaviour of other public relays and seeds;
- RAM/flash reduction and rekey initiation.

Please include the board, core version, and the Serial output when reporting a problem.

## Credits and license

This library exists because of other people's work:

- **[nostr-vpn](https://github.com/mmalmi/nostr-vpn)** by the Nostr VPN contributors (copyright Sirius Business Ltd; GitHub user `mmalmi`) — the protocol, the signed-roster format, mesh-IP rules, the public seed nodes and the apps this library interoperates with. Releases are also published at [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn). MIT licensed.
- **FIPS** — the mesh protocol nostr-vpn builds on: the [original project by jmcorgan](https://github.com/jmcorgan/fips) and nostr-vpn's [independently evolved fork](https://github.com/mmalmi/fips).
- **[Nostr](https://nostr.com)** — the open protocol for identity and signed events. Protocol repository: [nostr-protocol/nostr](https://github.com/nostr-protocol/nostr); specifications (NIPs): [nostr-protocol/nips](https://github.com/nostr-protocol/nips), notably [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md).
- **[libsecp256k1](https://github.com/bitcoin-core/secp256k1)** (Bitcoin Core) — elliptic-curve primitives, MIT.
- The Nostr control layer's tests use [nostr-tools](https://github.com/nbd-wtf/nostr-tools) as an independent reference.

`nvpn-esp32` is released under the **MIT License** (see [LICENSE](LICENSE), which keeps the original nostr-vpn copyright notice because this project derives from its logic); the vendored libsecp256k1 keeps its own license in `third_party/secp256k1/COPYING`.
