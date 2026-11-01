[README.md](https://github.com/user-attachments/files/34238751/README.md)
# nvpn-esp32

ไลบรารี C (ไม่ใช้ heap) ที่แยกส่วน **control plane** ของ [nostr-vpn](https://github.com/mmalmi/nostr-vpn) ออกมาให้รันบน ESP32 ได้
ใช้กับ ESP-IDF (เป็น component) และ PlatformIO ได้

> **ขอบเขตที่ต้องรู้ก่อน:** ไลบรารีนี้ **ยังไม่ใช่ VPN client เต็มรูปแบบ** — ไม่ได้ทำ data plane (FIPS)
> ดูหัวข้อ "สิ่งที่ยังไม่มี" ด้านล่าง

## มีอะไรบ้าง

| โมดูล | ทำอะไร | ต้นฉบับใน nostr-vpn |
|---|---|---|
| Identity | คีย์ Nostr (x-only secp256k1), hex ⇄ `npub`, เซ็น/ตรวจ BIP-340 | `identity_bridge`, `config_defaults` |
| Network ID / IP | normalize `network_id`, คำนวณ IP `10.44.x.y` ของแต่ละเครื่อง | `network_routes::derive_mesh_tunnel_ip` |
| Signed roster | ตรวจ event kind 30388 (event id + ลายเซ็น + tags) แล้วแปลงเป็น struct | `fips_control::SignedRoster` |
| Roster policy | อัปเดตเฉพาะที่เซ็นโดย admin ปัจจุบัน + ใหม่กว่าเท่านั้น, ตรวจอายุ (7 วัน / อนาคต 10 นาที) | `signed_rosters`, `join_requests` |
| Admission | ตรวจแพ็กเก็ต IPv4 ขาเข้า (source ต้องเป็น IP ของ peer ที่ยืนยันตัวแล้ว) และเลือก peer ปลายทางขาออก | `fips_mesh` (แนวคิด) |
| MagicDNS | ตอบ A record ของชื่อ alias (`<alias>` และ `<alias>.nvpn`) | `magic_dns`, `config_magic_dns` |

ไม่มี dynamic allocation; RAM หลักคือ `nvpn_roster_t` ≈ **4.5 KiB** (ปรับได้ด้วย `NVPN_MAX_MEMBERS` ฯลฯ),
stack ตอน `nvpn_roster_verify` ≈ **2 KiB** (ตั้ง main task stack ≥ 6–8 KiB)
libsecp256k1 ที่แถมมา (`third_party/`) ตั้งค่าตาราง precompute ขนาดเล็ก (window 4) เพื่อประหยัด flash

## ใช้งาน

```c
#include "nvpn.h"

static nvpn_roster_t roster;                    // ใหญ่ ~4.5KiB: ใช้ static/heap ไม่ใช่ stack

uint8_t sk[32]; esp_fill_random(sk, 32);        // เก็บใน NVS
uint8_t pk[32]; nvpn_pubkey_from_secret(sk, pk);

int rc = nvpn_roster_verify(json, len, &roster); // รับ event JSON หรือ {"event":{...}}
uint8_t ip[4]; nvpn_derive_tunnel_ip(roster.network_id, pk, ip);   // 10.44.x.y
```

ดูตัวอย่างเต็มที่ `examples/esp-idf-magicdns/` (สร้าง identity, ตรวจ roster, เปิด MagicDNS บน UDP/53)

- **ESP-IDF:** วางโฟลเดอร์นี้ใน `components/nvpn-esp32` แล้ว `REQUIRES nvpn-esp32`
- **PlatformIO:** ใส่ใน `lib/` หรือ `lib_deps = file://...` (`library.json` มีให้แล้ว)

## การทดสอบ (ทำบนเครื่อง host แล้ว ไม่ได้ทดสอบบนบอร์ดจริง)

```bash
cd test && make test       # 1,215 checks
make asan                  # ASan + UBSan
```

ค่าที่คาดหวังทั้งหมดสร้างจากโค้ด **Rust ต้นฉบับ** (`test/refgen`, ใช้ crate `nostr` 0.44 และอัลกอริทึมที่คัดลอกจาก `nostr-vpn-core`):
network id, IP derivation, npub, label ของ MagicDNS, และ roster 14 แบบ (ทั้งที่ผ่านและต้องถูกปฏิเสธ เช่น แก้ tag, ลายเซ็นเสีย,
kind ผิด, สมาชิกเกินความจุ, อักขระพิเศษ/emoji/`\u` escape) รวมถึงทดสอบแก้ทีละไบต์และตัดทอนทุกความยาว
ผลลัพธ์ยังรันซ้ำด้วยโหมด field/scalar แบบ 32-bit (`USE_FIELD_10X26`) ที่ ESP32 ใช้จริง
สร้าง vectors ใหม่: `cd test/refgen && cargo run > ../vectors.json && cd .. && python3 gen_vectors.py`

## สิ่งที่ยังไม่มี (และเหตุผล)

- **FIPS data plane** (Noise session, discovery, NAT traversal, FIPS-TCP): โค้ดอยู่ใน crate ภายนอก (`nvpn-fips-*`) ที่ไม่ได้อยู่ใน zip
  และ nostr-vpn ระบุว่ารูปแบบ wire เป็นของ FIPS — จึงยังส่ง/รับแพ็กเก็ตเข้า mesh จริงจาก ESP32 ไม่ได้
  ต้องมีสเปก/ซอร์ส FIPS ก่อน แล้วค่อยเพิ่มบนฐานนี้ (ESP32 มี ChaCha20-Poly1305 ใน mbedTLS และ secp256k1 ที่แถมมาแล้ว)
- **การ join/approve อัตโนมัติ** (`nvpn://join-request/…`, ส่ง roster ผ่าน FIPS-TCP): รูปแบบ bootstrap อยู่ใน crate `nostr-identity` ภายนอก
  ตอนนี้ต้อง provision roster เอง (วาง event JSON + ระบุ admin ที่เชื่อถือ ผ่าน `nvpn_roster_bootstrap`)
- Paid exits / Cashu, secure DNS (DoH), WireGuard upstream, exit-node routing — ไม่เหมาะกับ MCU และไม่ได้พอร์ต
- `trim`/whitespace ใช้ ASCII เท่านั้น (ต้นฉบับ Rust ใช้ Unicode whitespace) ต่างกันเฉพาะ input ที่มี whitespace แปลก ๆ
- alias ยาวเกิน 63 ไบต์ถูกตัด; `name`/alias ไม่ผ่านการ uniquify แบบเดียวกับแอป (ชื่อซ้ำจะ resolve ไปที่ตัวแรก)

## ถ้าต้องการให้ ESP32 "เข้าถึง" เครือข่าย nostr-vpn ตอนนี้

ให้เครื่อง Linux/Raspberry Pi ที่รัน `nvpn` ทำหน้าที่ gateway (nostr-vpn รองรับ subnet route) แล้วให้ ESP32 อยู่ใน LAN เดียวกับ gateway —
ESP32 ไม่ต้องรู้จัก VPN เลย ไลบรารีนี้เหมาะกับงานที่ ESP32 ต้องตรวจสอบสมาชิก/ตอบชื่อ MagicDNS/คำนวณ IP เอง

## FIPS data plane (leaf node) — `include/fips.h`

ไลบรารีมี FIPS แบบ sans-IO ที่เป็น **leaf node** (ไม่ forward ให้ใคร): FMP link (Noise IK) ไปยัง upstream ตัวเดียว + เข้าร่วมเมช (TreeAnnounce/FilterAnnounce/Lookup) + FSP session (Noise XK ทั้งฝั่ง initiator และ responder) ผ่านหลายฮอป + ส่ง/รับ datagram ตามพอร์ตและ EndpointData
- ไม่ใช้ heap; ผู้ใช้ส่ง callback `send/random/on_data` และป้อนเวลา (ms) เอง
- ทดสอบ interop กับ daemon `fips` (Rust) จริงบน loopback: link ขึ้น (state UP), session XK established, daemon รับ DataPacket
- ตัวอย่าง Linux: `test/Makefile` target `fips_client` (`examples/host-udp/fips_client.c`)
- **ข้อจำกัด**: ไม่ตอบ MMP report; ยังไม่มี rekey (ฝั่งตรงข้ามเริ่ม rekey แล้วล้มเหลวโดยไม่กระทบลิงก์ ทดสอบในเครื่องแล้ว แต่ไม่มีการหมุนคีย์); ไม่ทำ hole punching ตรง (ทราฟฟิกผ่าน upstream เสมอ)

### ตัวอย่าง ESP-IDF: `examples/esp-idf-fips`
```
cd examples/esp-idf-fips
idf.py set-target esp32      # หรือ esp32s3 / esp32c3
idf.py menuconfig            # "Example Connection Configuration" (Wi-Fi) และ "FIPS leaf example" (upstream host/port/pubkey, dest pubkey)
idf.py build flash monitor
```
- บอร์ดสร้าง identity ครั้งแรกเก็บใน NVS และพิมพ์ `my identity: npub1...` ออก serial (เพิ่มใน ACL ของ upstream ถ้ามี)
- upstream ต้อง bind UDP ที่ `0.0.0.0:2121` (ไม่ใช่ 127.0.0.1) และเข้าถึงได้จากบอร์ด
- ถ้าตั้ง `FIPS_DEST_PUBKEY` บอร์ดจะเปิด session ไปยังปลายทางและส่งข้อความทุก 10 วินาที; datagram ขาเข้าจะถูก log
- สถานะ: ผ่านการเช็ค syntax ด้วย header จำลองเท่านั้น ยังไม่ได้ build ด้วย ESP-IDF จริงหรือรันบนบอร์ด

### Arduino IDE
ใช้ `tools/make_arduino.sh <out_dir>` สร้างโฟลเดอร์ `nvpn-esp32/` (library.properties + src/ แบบแบน) แล้ว zip; ติดตั้งด้วย Sketch > Include Library > Add .ZIP Library. ตัวอย่าง: File > Examples > nvpn-esp32 > FipsLeaf (เลือกบอร์ด ESP32)

## วงแลนด์เสมือน (virtual LAN) — `nvpn_tunnel.h` / `nvpn_netif.h`

`nvpn_tunnel` (sans-IO) ต่อ IPv4 packet เข้ากับ FIPS แบบเดียวกับ nostr-vpn: แพ็กเก็ตขาออก → หา peer จาก roster (10.44.x.y) → session Noise XK → FSP **EndpointData (msg type 0x15, body = IP packet ดิบ)**; ขาเข้าผ่าน `nvpn_admit_inbound` (ตรวจ src/dst IP กับ roster) ก่อนส่งให้ IP stack รับ session ที่เพื่อนเริ่มได้ (เฉพาะสมาชิก roster) และเปิด session เองเมื่อมีแพ็กเก็ตไป peer ใหม่ (เก็บแพ็กเก็ตแรกไว้ 1 ตัว/peer ระหว่างตั้ง session)

`nvpn_netif` (ESP-IDF / Arduino-ESP32) สร้าง lwIP netif `nv0` ที่มี mesh IP `10.44.x.y/16` — หลัง `nvpn_netif_start()` โปรแกรมบนบอร์ดใช้ socket ปกติ (UDP/TCP/HTTP/MQTT) ไปยัง mesh IP ของสมาชิกอื่นได้ และสมาชิกอื่น ping/เชื่อมต่อเข้าบอร์ดได้ ตัวอย่าง: `examples/esp-idf-vlan`, `examples/arduino/VirtualLan.ino`

ที่ทดสอบแล้ว (host, loopback, กับ node ที่ build จาก crate `nvpn-fips-core 0.4.107` ตัวเดียวกับที่ nostr-vpn ใช้ ดู `test/interop-rs`):
- C ส่ง ICMP echo → ได้ echo reply กลับ ผ่านการกรอง roster (`make tunnel_ping`)
- node ของ nostr-vpn เป็นฝ่ายเริ่ม session ไปหา C แล้วส่งแพ็กเก็ตเข้ามา ผ่านการกรอง roster

ข้อจำกัดที่ต้องรู้: ทดสอบบนบอร์ดจริงแล้วแบบต่อตรงกับ PC ในวง LAN เดียวกัน (ping, UDP, TCP/HTTP); ส่วน lwIP netif ยังไม่ได้ compile กับ ESP-IDF จริง (Arduino ใช้งานได้); เป็น leaf (ไม่ forward ให้คนอื่น); ยังไม่มี rekey; รองรับ IPv4 ภายใน 10.44.0.0/16 เท่านั้น; ไม่ใช่ broker — ถ้าจะแทน MQTT ต้องรัน broker/โปรโตคอลของคุณเองบนวงนี้ (เช่น MQTT broker บนเครื่องอื่นในวง แล้วบอร์ดเชื่อมไปที่ mesh IP ของมัน)

คู่มือทดสอบทีละขั้น (PC Windows + มือถือ): `docs/TESTING.md`; เครื่องมือ: `tools/extract_roster.py`, `tools/mesh_ip.py`, `tools/pc_echo.py`, `tools/vlan_check.py`

### ใช้ข้ามเครือข่าย (Wi-Fi ไหนก็ได้) ผ่านโหนดสาธารณะ

ถ้าตั้ง upstream เป็นโหนดสาธารณะของโปรเจกต์ nostr-vpn (ค่าเริ่มต้นของแอป: `fips1.iris.to:51820` npub `npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd`, `fips2.iris.to:51820` npub `npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh`) บอร์ดต่อ *ออก* ไปหาโหนดนั้นด้วย UDP (ผ่าน NAT/CGNAT ได้โดยไม่ต้องเปิดพอร์ต router) แล้วคุยกับเพื่อนในวงที่ต่อโหนดเดียวกันผ่านการส่งต่อหลายฮอป: บอร์ดประกาศตัวเอง (TreeAnnounce + FilterAnnounce), หาพิกัดปลายทางด้วย LookupRequest, เปิด session Noise XK แบบ end-to-end (โหนดกลางเห็นแต่ข้อมูลเข้ารหัส)

- ทดสอบแล้ว (เครื่อง host, node อ้างอิงจาก `nvpn-fips-core 0.4.107`): `test/mesh3.sh` (leaf → seed → "PC": ping ขาออก 100/100, ขาเข้า, ต่อเนื่อง 100 วินาที), `test/mesh3_restart.sh` (รีสตาร์ท "PC" กลางทาง บอร์ดเปิด session ใหม่เองภายใน ~20 วินาที), `test/direct_inbound.sh`; ผ่านทั้งใต้ ASan/UBSan
- **ยังไม่ได้ทดสอบกับโหนด iris.to จริง** (sandbox ที่พัฒนาเข้าอินเทอร์เน็ตไม่ได้): ไม่ทราบนโยบายของโหนดสาธารณะ (รับ leaf แปลกหน้าไหม, จำกัดอัตราไหม, รุ่นซอฟต์แวร์) และต้องเป็นฝั่ง PC ที่ต่อโหนดเดียวกัน (nostr-vpn เปิด bootstrap ไว้เป็นค่าเริ่มต้น)
- โหนดสาธารณะเป็นของบุคคลที่สาม (ฟรีแต่ไม่รับประกัน) ถ้าต้องการความแน่นอนให้รัน `fips` เองบนเครื่องที่มี IP สาธารณะแล้วใส่เป็น `UP_HOST`/`UP_PUBKEY` (ทั้งบอร์ดและ PC ต้องต่อเข้าโหนดนั้น)
- ความหน่วงสูงกว่าต่อตรง (ผ่านเซิร์ฟเวอร์) และแบนด์วิดท์ขึ้นกับโหนดกลาง
