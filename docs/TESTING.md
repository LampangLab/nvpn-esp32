# คู่มือทดสอบ: ESP32 ↔ Nostr VPN (PC Windows) ↔ มือถือ

เครือข่ายตัวอย่างของคุณ: ชื่อ **JMCU**, PC นี้เป็น Admin, VPN IP `10.44.53.242`,
Device ID (admin) `npub1y9d8374tfxnjjhh7h67yyeqj449qe5xpyqp4492r3ur6kgc6n0jsqu0mu7` (กด Copy ในแอปเพื่อความชัวร์)

แผน: ให้ **PC เป็น upstream node** ของบอร์ด (บอร์ดต่อ UDP เข้า PC) แล้วทดสอบเป็นขั้น ๆ — ผ่านขั้นไหนค่อยไปขั้นถัดไป

## ขั้น 0 — ทดสอบบนเครื่อง (ไม่ต้องมีบอร์ด) — ผ่านแล้วในเครื่องผม
    cd test && make test && make selftest        # 1215 + 12 checks
    cd interop-rs && cargo build --release       # node อ้างอิงจาก nvpn-fips-core จริง
    ../tunnel_ping ...                           # ดู interop-rs/README.md

## ขั้น 1 — ทดสอบการคำนวณบนบอร์ด (ไม่ใช้ Wi-Fi)
Arduino IDE: File → Examples → nvpn-esp32 → **SelfTest** → อัปโหลด → Serial Monitor 115200
ต้องเห็น `RESULT: 12 passed, 0 failed` (แต่ละบรรทัดมีเวลาเป็น µs ส่งมาให้ผมดูด้วยก็ดี)

## ขั้น 2 — เอา npub ของบอร์ด
อัปโหลด **VirtualLan** โดยยังไม่ต้องแก้ค่าอะไร (ค่าว่าง) → Serial แสดง
`this device: npub1...` (ก่อนจะฟ้องว่าต้องตั้งค่า) — คัดลอก npub นี้

## ขั้น 3 — เพิ่มบอร์ดเข้า roster ของ JMCU
แอปมือถือ/เดสก์ท็อปเพิ่มอุปกรณ์ผ่าน "Join Request" ที่ลงนามแล้ว ซึ่งบอร์ดสร้างเองยังไม่ได้ จึงเพิ่มผ่าน CLI `nvpn` แทน:

1. เปิดแอป Nostr VPN กดปุ่ม **Off → On** ก่อน (แอปบังคับให้เปิดเครือข่ายก่อนเพิ่มอุปกรณ์)
2. เปิด PowerShell (ถ้าติดตั้ง `nvpn` แล้ว; ไม่งั้นโหลด CLI จากหน้า release ของ nostr-vpn):

       nvpn status                                  # ดูว่าเห็นเครือข่าย JMCU และ config path ใด
       nvpn set --device <npub ของ PC> --device <npub ของบอร์ด>

   **สำคัญ:** `--device` คือรายชื่อทั้งหมดของ roster (ไม่ใช่การ "เพิ่ม") ใส่ทุกเครื่องที่ต้องการให้อยู่ในวง
   ถ้ามีมือถืออยู่แล้วต้องใส่ npub มือถือด้วย ไม่งั้นจะถูกถอดออก
   ถ้า `nvpn` ไม่เจอ config เดียวกับแอป ให้ใส่ `--config` ชี้ไฟล์ของแอป (มักอยู่ที่ `%APPDATA%\nvpn\config.toml`
   หรือ `C:\ProgramData\Nostr VPN\config.toml` — ตรวจด้วย `nvpn status`)
3. รอให้แอป sign roster ใหม่ (แอปจะแสดงบอร์ดในรายการ Devices) แล้วหาไฟล์ `signed-rosters.json` ที่อยู่โฟลเดอร์เดียวกับ config:

       python tools\extract_roster.py "C:\...\signed-rosters.json" > roster.json

   สคริปต์พิมพ์ network id, admin และ **mesh IP ของทุกคนในวง** (รวม IP ของบอร์ด) ออก stderr
   ตรวจให้ชัวร์ว่า IP ของ PC = `10.44.53.242` (ตรงกับในแอป แสดงว่า network id ถูก)
   คำนวณ IP แยกได้ด้วย `python tools\mesh_ip.py <network_id> <npub>`

## ขั้น 4 — ตั้งค่าและอัปโหลดบอร์ด (VirtualLan.ino)
| ตัวแปร | ค่า |
|---|---|
| `WIFI_SSID/WIFI_PASS` | Wi-Fi เดียวกับ PC |
| `UP_HOST` | IP LAN ของ PC (`ipconfig`) |
| `UP_PORT` | `51820` (พอร์ต UDP ปกติของ nostr-vpn; ถ้าแอปตั้งไว้อย่างอื่นใช้ตามนั้น) |
| `UP_PUBKEY` | npub ของ PC (admin) — PC เป็น upstream |
| `TRUSTED_ADMIN` | npub ของ PC (คนที่ลงนาม roster) |
| `ROSTER_JSON` | เนื้อหาบรรทัดเดียวจาก roster.json (อยู่ใน `R"JSON(...)JSON"`) |
| `PEER_IP` | `10.44.53.242` (เปิดโหมดทดสอบอัตโนมัติ) |

Windows Firewall (โหมดต่อตรงในวง LAN): อนุญาต UDP 51820 ขาเข้า (เช่น `netsh advfirewall firewall add rule name="nvpn-fips" dir=in action=allow protocol=UDP localport=51820`) และถ้าใช้ `pc_echo.py` อนุญาต UDP 7777 กับ TCP 8080 ด้วย (ไม่เช่นนั้นบอร์ดเริ่มส่งไปหา PC ไม่ได้ ทั้งที่ ping จาก PC ผ่าน)

Serial ที่ควรเห็น:

    nvpn_netif_start -> 0
    mesh IP 10.44.x.y/16
    FIPS link UP
    link UP tx .. rx ..

### โหมดข้ามเครือข่าย (`USE_PUBLIC_SEED 1`) — Wi-Fi ไหนก็ได้
ในสเก็ตช์ `VirtualLan_JMCU.ino` / `VirtualLan.ino` ตั้ง `#define USE_PUBLIC_SEED 1` (ค่าเริ่มต้น): บอร์ดต่อไปที่โหนดสาธารณะ `fips1.iris.to:51820` แทนการต่อตรงหา PC จึงไม่ต้องใช้ IP ของ PC, port-forward, หรือ Wi-Fi เดียวกัน สิ่งที่ต้องมี: PC เปิดแอป nostr-vpn และออนไลน์ (แอปต่อโหนดสาธารณะอยู่แล้วโดยค่าเริ่มต้น), บอร์ดอยู่ใน roster (ขั้น 3)
Serial จะมีบรรทัดเพิ่ม `mesh depth=N lookups=N sessions=N`: `depth>0` = ได้รับ TreeAnnounce จากโหนดกลางแล้ว, `lookups>0` ค้าง = กำลังหาพิกัดของ PC, `sessions=1` = session ถึง PC ขึ้นแล้ว
ตรวจเบื้องต้น: ถ้า `link UP` แต่ `depth=0` นาน → โหนดกลางไม่ส่ง tree ให้ (นโยบาย/รุ่นต่างกัน); ถ้า `depth>0` แต่ lookup ไม่เจอ → PC อาจไม่ได้ต่อโหนดเดียวกัน หรือยังไม่ออนไลน์
**ยังไม่ได้ทดสอบกับโหนด iris.to จริง** ผลที่ได้จากบอร์ดคุณจะเป็นครั้งแรก

## ขั้น 5 — ทดสอบวง (บอร์ด ↔ PC)
บน PC รัน (ต้อง On อยู่):

    python tools\pc_echo.py                      # UDP echo :7777 และ HTTP :8080
    python tools\vlan_check.py <mesh IP ของบอร์ด> # ping + UDP echo + HTTP ไปหาบอร์ด

ฝั่งบอร์ด Serial จะพิมพ์ทุก 15 วินาที: `TEST udp_echo PASS rtt=.. ms` และ `TEST tcp_http PASS`
ผ่านทั้งสองฝั่ง = วงแลนด์เสมือนบอร์ด↔PC ทำงานจริง

## ขั้น 6 — มือถือ
ให้มือถืออยู่ใน roster เดียวกัน (ใส่ npub ในขั้น 3 ด้วย) เปิดแอปมือถือ On แล้ว ping `<mesh IP ของบอร์ด>` จากมือถือ
(ใช้แอป ping ใด ๆ) ขั้นนี้ผ่าน PC เป็นตัวกลางและ **ผมยังไม่เคยทดสอบแบบหลายฮอป** อาจไม่ผ่านในรอบแรก
ถ้าไม่ผ่าน ส่งกลับมา: Serial log ของบอร์ด + `nvpn status --json` ของ PC + ผลขั้น 5

## ตารางแก้ปัญหา
| อาการ | ตรวจ |
|---|---|
| `roster rejected (-6/-7/-11)` | ลงนามโดยคนที่ไม่ใช่ TRUSTED_ADMIN, JSON ไม่ครบ/ไม่ใช่ object `event` |
| `tunnel init failed` | npub บอร์ดยังไม่อยู่ใน roster (ทำขั้น 3 ใหม่) |
| link ไม่ขึ้น (ค้าง HANDSHAKING) | UP_HOST/พอร์ตผิด, ไฟร์วอลล์, แอปยัง Off, UP_PUBKEY ไม่ตรงกับ PC |
| link ขึ้น แต่ ping ไม่ตอบ | บอร์ดไม่อยู่ใน roster ที่ PC ใช้อยู่ (PC ยังไม่ได้ sign ใหม่) ดู Devices ในแอป |
| `rejected` ใน stats เพิ่ม | แพ็กเก็ตจาก peer ที่ IP ต้นทางไม่ตรง roster (network id ไม่ตรงกัน) |

## อ่านบรรทัด `RK` (trace rekey / บทบาท)

เฟิร์มแวร์ตัวอย่างพิมพ์บรรทัด `RK #n t=…s link_tx=… link_rx=… <เหตุการณ์>` ทุกครั้งที่เกิด link-up, rekey ของ FMP/FSP หรือเปลี่ยนบทบาท (Client-Only/TreeAnnounce) ไม่มีกุญแจหรือข้อมูลส่วนตัวในบรรทัดเหล่านี้ ดูรายละเอียดใน [INTEROP.md](INTEROP.md) ถ้าจะรายงานให้ผู้พัฒนา nostr-vpn ให้เก็บ Serial 10–15 นาทีพร้อม `daemon.log` ของ PC ช่วงเวลาเดียวกัน
