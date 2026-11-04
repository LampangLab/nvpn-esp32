/* nvpn-esp32 on-device self-test. No Wi-Fi needed. Open Serial Monitor at 115200:
 * every line must say PASS and the last line "RESULT: N passed, 0 failed". Timings show handshake cost. */
#include "selftest_core.h"

static void logLine(const char *s) { Serial.println(s); }
static unsigned long us(void) { return micros(); }

void setup() {
  Serial.begin(115200);
  delay(1500);
  static st_t t = {logLine, us, 0, 0};
  Serial.println("nvpn-esp32 self-test");
  selftest_run(&t);
}
void loop() { delay(1000); }
