/* FIPS leaf node on ESP32 (Arduino core): link to an upstream `fips` daemon over UDP,
 * optionally open an end-to-end session and send a datagram every 10 s.
 * Fill in the settings below. NOT yet verified on real hardware. */
#include <WiFi.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include "esp_random.h"
#include "fips.h"
#include "nvpn.h"

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";
const char *UP_HOST   = "192.168.1.10";   // upstream FIPS node (UDP bind must be 0.0.0.0:2121)
const uint16_t UP_PORT = 2121;
const char *UP_PUBKEY = "";               // upstream npub1... or 64-char hex
const char *DEST_PUBKEY = "";             // optional: destination node for a test message
const uint16_t DEST_PORT = 7;
const char *MESSAGE = "hello from esp32";

static fips_t node;      // several KiB, static
static WiFiUDP udp;
static IPAddress upIp;
static uint8_t dest[32];
static bool haveDest = false;

static void ioSend(void *, const uint8_t *p, size_t n) { udp.beginPacket(upIp, UP_PORT); udp.write(p, n); udp.endPacket(); }
static void ioRandom(void *, uint8_t *b, size_t n) { esp_fill_random(b, n); }
static void ioData(void *, const uint8_t src[16], uint16_t sp, uint16_t dp, const uint8_t *p, size_t n) {
  char hex[33]; nvpn_hex_encode(src, 16, hex);
  Serial.printf("DATA from %s port %u->%u (%u bytes): %.*s\n", hex, sp, dp, (unsigned)n, (int)n, (const char *)p);
}

void setup() {
  uint8_t sk[32], pk[32], up[32]; char npub[70]; Preferences prefs;
  Serial.begin(115200);
  prefs.begin("fips", false);
  if (prefs.getBytes("sk", sk, 32) != 32) {
    do { esp_fill_random(sk, 32); } while (nvpn_pubkey_from_secret(sk, pk) != NVPN_OK);
    prefs.putBytes("sk", sk, 32);
  }
  prefs.end();
  { uint8_t seed[32]; esp_fill_random(seed, 32); nvpn_secp_randomize(seed); }
  nvpn_pubkey_from_secret(sk, pk);
  if (nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK) Serial.printf("my identity: %s\n", npub);
  if (nvpn_pubkey_parse(UP_PUBKEY, up) != NVPN_OK) { Serial.println("set UP_PUBKEY"); while (true) delay(1000); }
  if (DEST_PUBKEY[0]) haveDest = nvpn_pubkey_parse(DEST_PUBKEY, dest) == NVPN_OK;
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(300);
  while (!WiFi.hostByName(UP_HOST, upIp)) delay(2000);
  udp.begin(0);
  static fips_io_t io = {ioSend, ioRandom, ioData, NULL};
  fips_init(&node, &io, sk, up);
  fips_connect(&node, millis());
}

void loop() {
  static uint8_t buf[FIPS_MTU + 64]; static int last = -1; static bool opened = false; static uint32_t lastTx = 0;
  int n = udp.parsePacket();
  if (n > 0 && n <= (int)sizeof buf) { n = udp.read(buf, sizeof buf); if (n > 0) fips_input(&node, buf, (size_t)n, millis()); }
  fips_tick(&node, millis());
  int st = fips_link_state(&node);
  if (st != last) { Serial.printf("link state -> %d (2 = UP)\n", st); last = st; if (st != FIPS_LINK_UP) opened = false; }
  if (haveDest && st == FIPS_LINK_UP) {
    if (!opened && fips_session_open(&node, dest, millis()) >= 0) opened = true;
    if (opened && fips_session_ready(&node, dest) && millis() - lastTx >= 10000) {
      int rc = fips_send_data(&node, dest, DEST_PORT, DEST_PORT, (const uint8_t *)MESSAGE, strlen(MESSAGE), millis());
      Serial.printf("sent rc=%d\n", rc); lastTx = millis();
    }
  }
  delay(5);
}
