/* ESP32 (Arduino core) as a member of a nostr-vpn virtual LAN. After the link is up the board has a
 * normal lwIP interface "nv0" (10.44.x.y/16): use WiFiClient/WiFiUDP/WebServer with other members'
 * mesh IPs, ping the board from them, etc. See esp-idf-vlan for the full explanation.
 * Verified on real hardware: direct to a nostr-vpn PC on the LAN (ping, UDP, TCP). The public-seed mode
 * (multi-hop) is verified against the reference node in a local 3-node test only. */
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <Preferences.h>
#include "esp_random.h"
#include "nvpn_netif.h"

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";
// ---- how the board reaches your PC ----
// 1 = through the public FIPS seed nodes that nostr-vpn itself uses by default (fips1.iris.to / fips2.iris.to):
//     works from ANY Wi-Fi, even behind CGNAT or a router you can't configure. The PC must be online and
//     running nostr-vpn (it connects to the same seeds), and the board must be in its roster.
// 0 = direct UDP to the PC on the same LAN (UP_HOST/UP_PUBKEY below).
#define USE_PUBLIC_SEED 1
#if USE_PUBLIC_SEED
const char *UP_HOST = "fips1.iris.to";
const uint16_t UP_PORT = 51820;
const char *UP_PUBKEY = "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd";  // fips1.iris.to (pinned)
// (second seed: fips2.iris.to  npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh)
#else
const char *UP_HOST = "192.168.1.10";     // your PC on the LAN
const uint16_t UP_PORT = 51820;           // nostr-vpn default listen port (plain fips daemon: 2121)
const char *UP_PUBKEY = "";               // the PC's npub1... or hex
#endif
const char *TRUSTED_ADMIN = "";           // admin npub1... or hex that signed the roster
// Optional self-test: mesh IP of another member running tools/pc_echo.py (udp 7777 + http 8080). "" = off.
const char *PEER_IP = "";
// Signed roster event JSON of your network (the "event" object). The board's own npub must be in it.
const char ROSTER_JSON[] = R"JSON({})JSON";

static nvpn_roster_t incoming, roster;    // roster must outlive the netif
static WiFiUDP echo;

void setup() {
  nvpn_netif_cfg_t cfg; Preferences prefs; uint8_t pk[32], admin[32]; char npub[70];
  Serial.begin(115200);
  memset(&cfg, 0, sizeof cfg);
  prefs.begin("nvpn", false);
  if (prefs.getBytes("sk", cfg.secret, 32) != 32) {
    do { esp_fill_random(cfg.secret, 32); } while (nvpn_pubkey_from_secret(cfg.secret, pk) != NVPN_OK);
    prefs.putBytes("sk", cfg.secret, 32);
  }
  prefs.end();
  { uint8_t seed[32]; esp_fill_random(seed, 32); nvpn_secp_randomize(seed); }
  nvpn_pubkey_from_secret(cfg.secret, pk);
  if (nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK) Serial.printf("this device: %s (add it to your nostr-vpn network)\n", npub);
  if (nvpn_pubkey_parse(UP_PUBKEY, cfg.upstream_pubkey) != NVPN_OK || nvpn_pubkey_parse(TRUSTED_ADMIN, admin) != NVPN_OK) { Serial.println("set UP_PUBKEY and TRUSTED_ADMIN"); while (true) delay(1000); }
  int rc = nvpn_roster_verify(ROSTER_JSON, sizeof ROSTER_JSON - 1, &incoming);
  if (rc != NVPN_OK || (rc = nvpn_roster_bootstrap(&roster, &incoming, admin)) != NVPN_OK) { Serial.printf("roster rejected (%d)\n", rc); while (true) delay(1000); }
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(300);
  cfg.upstream_host = UP_HOST; cfg.upstream_port = UP_PORT; cfg.roster = &roster;
  rc = nvpn_netif_start(&cfg);
  Serial.printf("nvpn_netif_start -> %d\n", rc);
  echo.begin(7777);                        // UDP echo on the mesh IP too (binds all interfaces)
}

static void probePeer() {
  static uint32_t seq;
  // UDP echo round trip
  WiFiUDP u; char msg[32]; snprintf(msg, sizeof msg, "esp-probe-%u", (unsigned)seq++);
  u.begin(0); u.beginPacket(PEER_IP, 7777); u.write((const uint8_t *)msg, strlen(msg)); u.endPacket();
  uint32_t t0 = millis(); bool ok = false;
  while (millis() - t0 < 2500) { int n = u.parsePacket(); if (n > 0) { char b[64] = {0}; u.read((uint8_t *)b, sizeof b - 1); ok = strcmp(b, msg) == 0; break; } delay(5); }
  Serial.printf("TEST udp_echo %s rtt=%lu ms\n", ok ? "PASS" : "FAIL", (unsigned long)(millis() - t0));
  u.stop();
  // TCP + HTTP
  WiFiClient c; bool http = false;
  if (c.connect(PEER_IP, 8080, 4000)) { c.print("GET / HTTP/1.0\r\n\r\n"); uint32_t t1 = millis(); while (millis() - t1 < 3000 && !c.available()) delay(5); String l = c.readStringUntil('\n'); http = l.indexOf("200") >= 0; c.stop(); }
  Serial.printf("TEST tcp_http %s\n", http ? "PASS" : "FAIL");
}

static void printHdr(const char *tag, const uint8_t *s, const uint8_t *d, uint8_t proto, unsigned len) {
  Serial.printf("%s %u.%u.%u.%u -> %u.%u.%u.%u proto=%u len=%u\n", tag, s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3], proto, len);
}

// ---- rekey/role trace: prints "RK ..." lines for new library events (no keys, no payloads) -------------------------
// t = board uptime, link_tx / link_rx = FMP frames sent / authenticated frames received so far (packet counts for context).
static const char *rkName(uint8_t k) {
  switch (k) {
    case 1: return "link-up";            case 2: return "link-down";
    case 3: return "FMP msg1 rx (upstream starts a LINK rekey; we are initiator-only and do not answer)";
    case 4: return "FMP K-flip (link key epoch changed)";
    case 5: return "FSP SessionSetup rx";  case 6: return "FSP msg3: new session";
    case 7: return "FSP msg3: REKEY (pending epoch stored)";  case 8: return "FSP cutover (pending epoch promoted)";
    case 9: return "FSP dead-peer reset";
    case 10: return "role: ClientSupport tx"; case 11: return "role: ClientSupport/ClientOnly rx (arg=type)";
    case 12: return "role: ClientOnly tx (arg=seq low byte)"; case 13: return "role: ClientOnly rx";
    case 14: return "role: TreeAnnounce tx"; case 15: return "role: fallback to TreeAnnounce (opt-in)";
    case 16: return "role: upstream lacks leaf support (no ClientSupport answer) - NOT advertising as router, waiting, retry every 30 s";
  }
  return "?";
}
static void rkPoll() {
  static uint32_t next = 0, lastStatus = 0; uint32_t total = 0; uint8_t role = 0; fips_trace_t e;
  nvpn_netif_trace(0, &e, &total, &role);
  if (total - next > FIPS_TRACE_N) next = total - FIPS_TRACE_N;            // some events were overwritten
  for (; next < total; next++)
    if (nvpn_netif_trace(next, &e, &total, &role))
      Serial.printf("RK #%u t=%lu.%03lus link_tx=%u link_rx=%u %s arg=%u\n", (unsigned)next, (unsigned long)(e.t_ms / 1000), (unsigned long)(e.t_ms % 1000), (unsigned)e.tx, (unsigned)e.rx, rkName(e.kind), (unsigned)e.arg);
  if (millis() - lastStatus > 30000) { lastStatus = millis(); Serial.printf("RK status role=%u (0 negotiating, 1 client-only, 2 TreeAnnounce, 3 waiting: upstream lacks leaf support) events=%u\n", (unsigned)role, (unsigned)total); }
}

void loop() {
  rkPoll();
  static uint32_t lastRej;
  if (millis() - lastRej > 30000) { lastRej = millis(); nvpn_tunnel_stats_t sr; nvpn_netif_stats(&sr); Serial.printf("REJ rr_tx=%u ctrl_ping=%u pong=%u n=%u not_ipv4=%u len=%u head=", (unsigned)sr.dg[17], (unsigned)sr.ctrl_ping_rx, (unsigned)sr.ctrl_pong_tx, (unsigned)sr.rx_rejected, (unsigned)sr.rej_not_ipv4, (unsigned)sr.last_rej_len); for (int i = 0; i < 24; i++) Serial.printf("%02x", sr.last_rej_head[i]); Serial.println(); }

  int n = echo.parsePacket();
  if (n > 0) { uint8_t b[512]; n = echo.read(b, sizeof b); echo.beginPacket(echo.remoteIP(), echo.remotePort()); echo.write(b, n); echo.endPacket(); }
  static uint32_t last; if (millis() - last > 10000) { last = millis(); nvpn_tunnel_stats_t st; nvpn_netif_stats(&st); Serial.printf("mesh depth=%u lookups=%u sessions=%u\n", (unsigned)st.tree_depth, (unsigned)st.lookups_active, (unsigned)st.sessions_up); Serial.printf("link %s state=%u | udp tx=%u err=%u rx=%u resends=%u last_rc=%d | ip tx=%u rx=%u dropped=%u rejected=%u\n", nvpn_netif_link_up() ? "UP" : "down", (unsigned)st.link_state, (unsigned)st.udp_tx, (unsigned)st.udp_tx_err, (unsigned)st.udp_rx, (unsigned)st.link_resends, (int)st.last_input_rc, (unsigned)st.tx_pkts, (unsigned)st.rx_pkts, (unsigned)st.tx_dropped, (unsigned)st.rx_rejected); printHdr("  last tx (non-icmp):", st.last_tx_src, st.last_tx_dst, st.last_tx_proto, st.last_tx_len); printHdr("  last rejected rx:  ", st.last_rej_src, st.last_rej_dst, st.last_rej_proto, st.last_rej_len); }
  static uint32_t lastProbe; if (PEER_IP[0] && nvpn_netif_link_up() && millis() - lastProbe > 15000) { lastProbe = millis(); probePeer(); }
  delay(2);
}
