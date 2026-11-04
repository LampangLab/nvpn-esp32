[README.th.md](https://github.com/user-attachments/files/34397174/README.th.md)
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
