/* host helper: nostr_tool sign <sk_hex> <created_at> <kind> <tags_json> <content>  -> event JSON
 *              nostr_tool check <pubkey> <created_at> <kind> <tags_json> <content> <id> <sig> -> OK / BAD(rc) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../examples/arduino/NostrBoard/nostr_event.h"
int main(int argc, char **argv) {
    static char work[4096], out[4096];
    if (argc == 7 && !strcmp(argv[1], "sign")) {
        uint8_t sk[32]; if (nvpn_hex_decode(argv[2], 64, sk, 32)) return 2;
        int n = nostr_event_sign(sk, strtoull(argv[3], 0, 10), atoi(argv[4]), argv[5], argv[6], work, sizeof work, out, sizeof out);
        if (n < 0) return 3; puts(out); return 0;
    }
    if (argc == 9 && !strcmp(argv[1], "check")) {
        int rc = nostr_event_check(argv[2], strtoull(argv[3], 0, 10), atoi(argv[4]), argv[5], argv[6], argv[7], argv[8], work, sizeof work);
        puts(rc == 0 ? "OK" : "BAD"); return rc == 0 ? 0 : 1;
    }
    return 2;
}
