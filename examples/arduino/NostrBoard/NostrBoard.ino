/* NostrBoard: control and monitor an ESP32 from a web page through a PUBLIC Nostr relay.
 *  - The board only makes an OUTBOUND secure WebSocket (wss://) to a relay, so it works behind any Wi-Fi / CGNAT
 *    / router you cannot configure, with no PC left on and no server of your own.
 *  - The board publishes its status (kind 21080, ephemeral: relays are not expected to store it, and it avoids NIP-78
 *    kind 30078 which is meant for private data) and listens for commands (kind 21078, ephemeral) addressed to it. Everything is signed (BIP-340); the board accepts commands only from keys in CONTROLLERS
 *    (or only harmless ones from anyone, see ALLOW_ANYONE). Content is signed, NOT encrypted.
 *  - Reply to a command: kind 21079.  Open web/index.html on a phone or PC to use it.
 * Libraries (Library Manager): "WebSockets" by Markus Sattler, "ArduinoJson" v7, and nvpn-esp32 (this repo).
 * NOT yet verified on hardware. Needs only Wi-Fi; it does not use the virtual-LAN part of nvpn-esp32. */
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <time.h>
#include "esp_random.h"
#include "nvpn.h"
#include "nostr_event.h"

const char *WIFI_SSID = "your-wifi-name";
const char *WIFI_PASS = "your-password";

const char *RELAY_HOST = "nos.lol";      // a public relay that accepts free writes; the web page must use the same one
const uint16_t RELAY_PORT = 443;
const char *RELAY_PATH = "/";
const char *BOARD_NAME = "board-1";

// Keys (npub1... or 64-hex) allowed to send privileged commands (led, ...). Copy yours from the web page ("my key").
const char *CONTROLLERS[] = { "" };      // e.g. { "npub1....", "npub1...." }
// true = anyone may send privileged commands (no key needed). Keep false unless the board controls nothing sensitive.
const bool ALLOW_ANYONE = false;

const int LED_PIN = 2;                   // example output
const int KIND_STATUS = 21080, KIND_CMD = 21078, KIND_REPLY = 21079;   // custom, unregistered kinds (see docs/NOSTR.md)
const uint32_t STATUS_EVERY_MS = 30000;
const int MAX_SKEW_S = 90;               // reject commands whose timestamp is older/newer than this (replay guard)

static WebSocketsClient ws;
static Preferences prefs;
static uint8_t sk[32], pk[32];
static char pkHex[65];
static uint8_t ctrl[8][32]; static int nctrl;
static char work[2304], evbuf[2048], msgbuf[2200];
static char seen[8][65]; static int seenN;
static bool ledOn;
static uint32_t lastStatus;

static uint64_t nowS() { return (uint64_t)time(nullptr); }

static bool isController(const uint8_t *who) {
  for (int i = 0; i < nctrl; i++) if (!memcmp(ctrl[i], who, 32)) return true;
  return false;
}

static void sendEvent(int kind, const char *tags, const char *content) {
  int n = nostr_event_sign(sk, nowS(), kind, tags, content, work, sizeof work, evbuf, sizeof evbuf);
  if (n < 0) { Serial.println("sign failed"); return; }
  snprintf(msgbuf, sizeof msgbuf, "[\"EVENT\",%s]", evbuf);
  ws.sendTXT(msgbuf);
}

static void publishStatus() {
  char c[200], t[80];
  snprintf(c, sizeof c, "{\"name\":\"%s\",\"up\":%lu,\"heap\":%u,\"rssi\":%d,\"led\":%d,\"t\":%llu}", BOARD_NAME,
           (unsigned long)(millis() / 1000), (unsigned)ESP.getFreeHeap(), (int)WiFi.RSSI(), ledOn ? 1 : 0, (unsigned long long)nowS());
  snprintf(t, sizeof t, "[[\"name\",\"%s\"]]", BOARD_NAME);
  sendEvent(KIND_STATUS, t, c);
  lastStatus = millis();
}

static void reply(const char *toPkHex, const char *eventId, bool ok, const char *msg) {
  char tags[200], c[160];
  snprintf(tags, sizeof tags, "[[\"p\",\"%s\"],[\"e\",\"%s\"]]", toPkHex, eventId);
  snprintf(c, sizeof c, "{\"ok\":%s,\"msg\":\"%s\"}", ok ? "true" : "false", msg);
  sendEvent(KIND_REPLY, tags, c);
}

/* Add your own commands here. `privileged` = sender is an allowed controller (or ALLOW_ANYONE). */
static void runCommand(const char *cmd, JsonVariantConst arg, bool privileged, const char *fromHex, const char *id) {
  if (!strcmp(cmd, "ping")) { reply(fromHex, id, true, "pong"); return; }
  if (!strcmp(cmd, "status")) { reply(fromHex, id, true, "status sent"); publishStatus(); return; }
  if (!privileged) { reply(fromHex, id, false, "not allowed"); return; }
  if (!strcmp(cmd, "led")) {
    if (arg.is<int>()) ledOn = arg.as<int>() != 0;
    else if (arg.is<const char *>() && !strcmp(arg.as<const char *>(), "toggle")) ledOn = !ledOn;
    else { reply(fromHex, id, false, "arg: 0, 1 or toggle"); return; }
    digitalWrite(LED_PIN, ledOn ? HIGH : LOW);
    reply(fromHex, id, true, ledOn ? "led on" : "led off"); publishStatus(); return;
  }
  reply(fromHex, id, false, "unknown command");
}

static void handleEvent(JsonObjectConst ev) {
  const char *id = ev["id"], *pub = ev["pubkey"], *content = ev["content"], *sig = ev["sig"];
  if (!id || !pub || !content || !sig || !ev["tags"].is<JsonArrayConst>() || (int)ev["kind"] != KIND_CMD) return;
  static char tagsJson[400];
  if (serializeJson(ev["tags"], tagsJson, sizeof tagsJson) >= sizeof tagsJson) return;
  uint64_t ts = ev["created_at"].as<uint64_t>();
  if (nostr_event_check(pub, ts, KIND_CMD, tagsJson, content, id, sig, work, sizeof work) != 0) { Serial.println("bad signature"); return; }
  uint64_t now = nowS();
  if (now > 1700000000ULL && (ts + MAX_SKEW_S < now || ts > now + MAX_SKEW_S)) { Serial.println("stale command"); return; }
  for (int i = 0; i < 8; i++) if (!strcmp(seen[i], id)) return;               // duplicate (several relays / replay)
  strncpy(seen[seenN++ & 7], id, 64);
  uint8_t who[32]; nvpn_hex_decode(pub, 64, who, 32);
  bool priv = ALLOW_ANYONE || isController(who);
  JsonDocument c;
  if (deserializeJson(c, content) || !c["cmd"].is<const char *>()) return;
  Serial.printf("cmd %s from %.8s priv=%d\n", c["cmd"].as<const char *>(), pub, priv);
  runCommand(c["cmd"], c["arg"], priv, pub, id);
}

static void onWs(WStype_t type, uint8_t *p, size_t len) {
  if (type == WStype_CONNECTED) {
    Serial.println("relay connected");
    snprintf(msgbuf, sizeof msgbuf, "[\"REQ\",\"cmd\",{\"kinds\":[%d],\"#p\":[\"%s\"],\"since\":%llu}]", KIND_CMD, pkHex, (unsigned long long)(nowS() - 5));
    ws.sendTXT(msgbuf);
    publishStatus();
  } else if (type == WStype_DISCONNECTED) {
    Serial.println("relay disconnected");
  } else if (type == WStype_TEXT) {
    static JsonDocument d;
    if (deserializeJson(d, (const char *)p, len)) return;
    const char *kind = d[0];
    if (kind && !strcmp(kind, "EVENT") && d[2].is<JsonObjectConst>()) handleEvent(d[2].as<JsonObjectConst>());
    else if (kind && (!strcmp(kind, "OK") || !strcmp(kind, "NOTICE") || !strcmp(kind, "CLOSED"))) Serial.printf("relay: %.*s\n", (int)(len > 160 ? 160 : len), (const char *)p);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  prefs.begin("nostr", false);
  if (prefs.getBytes("sk", sk, 32) != 32) {
    do { esp_fill_random(sk, 32); } while (nvpn_pubkey_from_secret(sk, pk) != NVPN_OK);
    prefs.putBytes("sk", sk, 32);
  }
  prefs.end();
  { uint8_t seed[32]; esp_fill_random(seed, 32); nvpn_secp_randomize(seed); }
  nvpn_pubkey_from_secret(sk, pk); nvpn_hex_encode(pk, 32, pkHex);
  char npub[70];
  if (nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK) Serial.printf("board key: %s\n           %s  (enter the npub on the web page)\n", npub, pkHex);
  for (size_t i = 0; i < sizeof CONTROLLERS / sizeof *CONTROLLERS && nctrl < 8; i++)
    if (CONTROLLERS[i][0] && nvpn_pubkey_parse(CONTROLLERS[i], ctrl[nctrl]) == NVPN_OK) nctrl++;
  Serial.printf("%d controller key(s)%s\n", nctrl, ALLOW_ANYONE ? ", ANYONE allowed" : "");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(300);
  Serial.printf("wifi %s\n", WiFi.localIP().toString().c_str());
  configTime(0, 0, "pool.ntp.org", "time.google.com");              // signatures and the replay guard need real time
  for (int i = 0; i < 60 && nowS() < 1700000000ULL; i++) delay(250);
  Serial.printf("time %s\n", nowS() > 1700000000ULL ? "ok" : "NOT SET (commands will be accepted without a time check)");
  ws.beginSSL(RELAY_HOST, RELAY_PORT, RELAY_PATH);   // note: without a CA/fingerprint this library does not verify the server certificate;
  ws.onEvent(onWs);                                   // events are signed, so a man in the middle can block but not forge commands
  ws.setReconnectInterval(5000);
  ws.enableHeartbeat(20000, 5000, 2);
}

void loop() {
  ws.loop();
  if (ws.isConnected() && millis() - lastStatus > STATUS_EVERY_MS) publishStatus();
}
