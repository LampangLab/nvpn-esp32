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


[README.th.md](https://github.com/user-attachments/files/34397196/README.th.md)
# nvpn-esp32 (ภาษาไทย)

**ให้ ESP32 เข้าร่วมเครือข่ายส่วนตัว [nostr-vpn](https://github.com/mmalmi/nostr-vpn) ได้จาก Wi-Fi ไหนก็ได้ หลัง NAT/CGNAT โดยไม่ต้องมีเซิร์ฟเวอร์ของตัวเอง**

[English README](README.md) · Repository: <https://github.com/LampangLab/nvpn-esp32>

> **ไม่เป็นทางการ:** โปรเจ็กต์นี้เป็นการพอร์ตโดยอิสระ ไม่ได้เกี่ยวข้องหรือได้รับการรับรองจาก nostr-vpn, FIPS, Nostr หรือ iris.to

ไลบรารี C (ไม่ใช้ heap) ที่ทำให้ ESP32 เป็นโหนดปลายทาง (leaf) ในเครือข่าย nostr-vpn: บอร์ดได้ IP เสมือน `10.44.x.y` เครื่องอื่นในวง (PC มือถือ บอร์ดอื่น) ping และเชื่อม TCP/UDP เข้าบอร์ดได้ และบอร์ดเชื่อมออกไปหาพวกเขาได้ ผ่านโหนดสาธารณะ FIPS แม้ทั้งสองฝั่งอยู่หลัง Wi-Fi ที่ตั้งค่า router ไม่ได้

ชั้นเสริม: ให้ใครก็ได้ที่มีหน้าเว็บ ดูสถานะและสั่งบอร์ดผ่าน relay **Nostr** สาธารณะ โดยไม่ต้องลงแอปหรือเปิด PC ทิ้งไว้ ดู [docs/NOSTR.md](docs/NOSTR.md)

## ทำอะไรได้

| ชั้น | สิ่งที่ได้ |
|---|---|
| Control plane | ตัวตน Nostr (BIP-340, `npub`), ตรวจ roster ที่แอดมินเซ็น (kind 30388), คำนวณ IP เหมือน nostr-vpn, กรองแพ็กเก็ต, MagicDNS |
| FIPS data plane | ลิงก์ Noise IK ไป upstream, เข้าร่วมเมช, เซสชัน Noise XK ปลายทางถึงปลายทางหลายฮอป, ส่ง IPv4 ดิบ, รับมือ rekey ที่ฝั่งตรงข้ามเริ่ม |
| วงแลนเสมือน | lwIP interface `nv0` บน Arduino-ESP32 ใช้ `WiFiClient`/`WiFiUDP`/`WebServer`/MQTT กับ IP ในวงได้เหมือนอยู่ LAN เดียวกัน |
| ชั้น Nostr (เสริม) | สถานะและคำสั่งผ่าน relay สาธารณะ พร้อมหน้าเว็บไฟล์เดียว |

## สถานะที่ยืนยันแล้ว (อย่าเชื่อเกินจริง)

ซอฟต์แวร์ระยะเริ่มต้น ยังไม่ผ่านการตรวจความปลอดภัย

- **ทดสอบบนบอร์ดจริงแล้ว** (Arduino-ESP32, Wi-Fi บ้าน, PC Windows รันแอป nostr-vpn 4.1.19): ต่อ node ใน LAN, ping สองทาง, UDP echo และ TCP/HTTP; ต่อโหนดสาธารณะ `fips2.iris.to` แล้วคุยกับ PC ผ่านโหนดนั้น รันราว 30 นาที ผ่าน UDP 114/123 และ TCP/HTTP 117/123 (ราว 7% ล้มเหลว RTT ปกติ 0.5–0.8 วินาที); self-test เข้ารหัสบนบอร์ด 12/12
- **ทดสอบบนเครื่อง host เท่านั้น:** ส่งต่อหลายฮอป leaf → seed → peer, session ขาเข้าผ่าน seed, กู้ session หลัง peer รีสตาร์ท, ชุดตรวจ 1,215 ข้อ (ค่าคาดหวังสร้างจากโค้ด Rust ต้นฉบับ), ASan/UBSan สะอาด
- **ยังไม่ได้ทดสอบ:** แอปมือถือ, สองเครือข่ายที่แยกกันจริง (ตอนทดสอบบนบอร์ด PC กับบอร์ดใช้ Wi-Fi เดียวกัน แต่ทราฟฟิกวิ่งผ่านโหนดสาธารณะ), การ build lwIP netif/ตัวอย่างด้วย ESP-IDF จริง, เสถียรภาพเกิน ~30 นาที, ชิป ESP32 รุ่นอื่น, ชั้น Nostr บนบอร์ดและ relay จริง
- **ข้อจำกัด:** เป็น leaf (ไม่ forward ให้คนอื่น) และเจรจาบทบาท Client-Only ของ FIPS (`ClientSupport`/`ClientOnly`) ถ้า upstream ไม่ตอบ (ไม่รองรับ leaf) จะ **ไม่ประกาศตัวเป็น router** แต่รายงานแล้วรอ (role 3 ลอง ClientSupport ซ้ำทุก 30 วิ; ถอยไป `TreeAnnounce` ได้เฉพาะเมื่อเปิด `allow_router_fallback` เอง) (รายละเอียดใน [docs/INTEROP.md](docs/INTEROP.md)), ไม่เริ่ม rekey เอง, MMP ส่งเฉพาะ session `ReceiverReport` (ไม่มี SenderReport และรายงานระดับลิงก์), ตอบเฉพาะ control frame Ping (ด้วย Pong) ไม่มี frame join/ack (แอปอาจขึ้น "waiting to confirm" ทั้งที่ข้อมูลเดินปกติ), ไม่ทำ hole punching, เฉพาะ IPv4 ใน `10.44.0.0/16`, ยังไม่ได้วัด/ลดการใช้ RAM

## เริ่มต้น (Arduino IDE)

1. โหลดไฟล์ **`nvpn-esp32-arduino.zip`** จากหน้า [Releases](../../releases) ของรีโปนี้ (**อย่า**ใช้ปุ่ม Download ZIP ของ GitHub เพราะได้ซอร์สทั้งรีโป ซึ่ง Arduino IDE ติดตั้งเป็นไลบรารีไม่ได้) แล้วไปที่ Sketch → Include Library → Add .ZIP Library เลือกไฟล์นั้น และเปิด IDE ใหม่ ถ้าเคยติดตั้งรุ่นเก่าให้ลบโฟลเดอร์ `nvpn-esp32` ใน `Documents/Arduino/libraries/` ก่อน (ถ้าจะสร้าง zip เองจากรีโปที่ clone: `tools/make_arduino.sh out && (cd out && zip -r nvpn-esp32-arduino.zip nvpn-esp32)` ต้องมี bash)
2. เปิด `examples/arduino/VirtualLan.ino` ตั้ง Wi-Fi, npub ของแอดมิน และวาง roster JSON ที่เซ็นแล้ว (`tools/extract_roster.py` ช่วยดึง)
3. อัปโหลด Serial (115200) จะพิมพ์ `this device: npub1…` ให้เพิ่มเข้าเครือข่ายที่เครื่องแอดมิน:
   `nvpn add-device --device npub1… --publish && nvpn reload` แล้ววาง roster ใหม่ลงสเก็ตช์และอัปโหลดอีกครั้ง
4. ping IP ของบอร์ดจากเครื่องอื่น (`tools/mesh_ip.py` คำนวณ IP จากกุญแจ)

ค่าเริ่มต้นใช้โหนดสาธารณะเดียวกับที่แอป nostr-vpn ใช้ (`fips1.iris.to` / `fips2.iris.to` พอร์ต 51820) ผู้ดูแล nostr-vpn แจ้งว่าอุปกรณ์เล็กอย่าง ESP32/MCU ใช้โหนดเหล่านี้ได้ ไม่จำเป็นต้องรัน seed เองเพียงเพราะอุปกรณ์มีทรัพยากรจำกัด ([nostr-vpn#157](https://github.com/mmalmi/nostr-vpn/issues/157)) แต่ยังเป็นเซิร์ฟเวอร์ของบุคคลที่สามที่ไม่มีการรับประกันบริการ จึงไม่ควรพึ่งพาในงานสำคัญ ถ้าต้องการความแน่นอนให้รัน `fips` เองแล้วตั้ง `UP_HOST` / `UP_PUBKEY`

คู่มือทดสอบทีละขั้น: [docs/TESTING.md](docs/TESTING.md) · ชั้น Nostr: [docs/NOSTR.md](docs/NOSTR.md)

## ความปลอดภัย

- ตัวอย่างเก็บกุญแจลับใน NVS แบบไม่เข้ารหัส ถ้าสำคัญให้เปิด flash/NVS encryption
- ชั้น Nostr **เซ็นแต่ไม่เข้ารหัส** และสเก็ตช์ไม่ตรวจใบรับรอง TLS ของ relay ห้ามใส่ความลับ และจำกัด `CONTROLLERS[]` ให้แคบ
- ห้ามใช้กับงานที่เกี่ยวกับความปลอดภัยของชีวิต/ทรัพย์สิน

## ร่วมพัฒนา

ยินดีรับ issue/PR โดยเฉพาะ: ผลทดสอบกับบอร์ดอื่นและเครือข่ายที่แยกกันจริง, การ build ESP-IDF, พฤติกรรมของ relay/seed อื่น, การลด RAM และการเริ่ม rekey เอง โปรดแนบรุ่นบอร์ด/คอร์และข้อความ Serial

## เครดิตและสัญญาอนุญาต

- **[nostr-vpn](https://github.com/mmalmi/nostr-vpn)** โดย Nostr VPN contributors (ลิขสิทธิ์ Sirius Business Ltd; GitHub: `mmalmi`) — โปรโตคอล รูปแบบ roster กฎ IP โหนดสาธารณะ และแอปที่ไลบรารีนี้ทำงานร่วมด้วย (MIT) ดาวน์โหลดได้ที่ [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn)
- **FIPS** โปรโตคอลเมชที่ nostr-vpn สร้างบน: [โปรเจ็กต์ดั้งเดิมของ jmcorgan](https://github.com/jmcorgan/fips) และ [ฟอร์กของ nostr-vpn](https://github.com/mmalmi/fips)
- **[Nostr](https://nostr.com)** โปรโตคอลเปิดสำหรับตัวตนและอีเวนต์ที่เซ็น: [nostr-protocol/nostr](https://github.com/nostr-protocol/nostr), ข้อกำหนด NIP: [nostr-protocol/nips](https://github.com/nostr-protocol/nips) (โดยเฉพาะ [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md))
- **[libsecp256k1](https://github.com/bitcoin-core/secp256k1)** (Bitcoin Core, MIT)
- [nostr-tools](https://github.com/nbd-wtf/nostr-tools) ใช้เป็นตัวอ้างอิงอิสระในการทดสอบชั้น Nostr

เผยแพร่ภายใต้ **MIT License** ดู [LICENSE](LICENSE) (คงประกาศลิขสิทธิ์ของ nostr-vpn เดิมไว้ เพราะอ้างอิงตรรกะของโปรเจ็กต์นั้น)
