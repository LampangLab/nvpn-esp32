/* Minimal Nostr (NIP-01) event helpers on top of nvpn-esp32's SHA-256 and BIP-340 Schnorr.
 * Plain C, header-only, no heap: usable from the Arduino sketch and from host tests. */
#ifndef NOSTR_EVENT_H
#define NOSTR_EVENT_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "nvpn.h"

/* JSON-escape per NIP-01 (only \n \" \\ \r \t \b \f are escaped). Returns length, or -1 if cap is too small. */
static inline int nostr_json_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (; *in; in++) {
        const char *rep = 0; char one[2] = {0, 0};
        switch (*in) {
        case '\n': rep = "\\n"; break; case '"': rep = "\\\""; break; case '\\': rep = "\\\\"; break;
        case '\r': rep = "\\r"; break; case '\t': rep = "\\t"; break; case '\b': rep = "\\b"; break;
        case '\f': rep = "\\f"; break; default: one[0] = *in; rep = one;
        }
        size_t l = strlen(rep);
        if (o + l + 1 > cap) return -1;
        memcpy(out + o, rep, l); o += l;
    }
    if (o + 1 > cap) return -1;
    out[o] = 0; return (int)o;
}

/* id = SHA256 of [0,"<pubkey>",<created_at>,<kind>,<tags_json>,"<content>"]. tags_json is the compact JSON array
 * of tags (e.g. [["p","ab.."]] or []). work/cap: scratch buffer for the serialization. Returns 0 on success. */
static inline int nostr_event_id(const char *pubkey_hex, uint64_t created_at, int kind, const char *tags_json,
                                 const char *content, char *work, size_t cap, uint8_t id[32]) {
    int n = snprintf(work, cap, "[0,\"%s\",%llu,%d,%s,\"", pubkey_hex, (unsigned long long)created_at, kind, tags_json);
    if (n < 0 || (size_t)n >= cap) return -1;
    int e = nostr_json_escape(content, work + n, cap - (size_t)n);
    if (e < 0 || (size_t)(n + e + 2) > cap) return -1;
    work[n + e] = '"'; work[n + e + 1] = ']';
    nvpn_sha256((const uint8_t *)work, (size_t)(n + e + 2), id);
    return 0;
}

/* Build and sign an event; writes the event JSON object (not the ["EVENT",..] wrapper) to out. Returns its length or -1. */
static inline int nostr_event_sign(const uint8_t secret[32], uint64_t created_at, int kind, const char *tags_json,
                                   const char *content, char *work, size_t work_cap, char *out, size_t out_cap) {
    uint8_t pk[32], id[32], sig[64]; char pkh[65], idh[65], sigh[129]; static char esc[1536];
    if (nvpn_pubkey_from_secret(secret, pk) != NVPN_OK) return -1;
    nvpn_hex_encode(pk, 32, pkh);
    if (nostr_event_id(pkh, created_at, kind, tags_json, content, work, work_cap, id)) return -1;
    if (nvpn_schnorr_sign(secret, id, 0, sig) != NVPN_OK) return -1;
    nvpn_hex_encode(id, 32, idh); nvpn_hex_encode(sig, 64, sigh);
    if (nostr_json_escape(content, esc, sizeof esc) < 0) return -1;
    int n = snprintf(out, out_cap, "{\"id\":\"%s\",\"pubkey\":\"%s\",\"created_at\":%llu,\"kind\":%d,\"tags\":%s,\"content\":\"%s\",\"sig\":\"%s\"}",
                     idh, pkh, (unsigned long long)created_at, kind, tags_json, esc, sigh);
    return (n < 0 || (size_t)n >= out_cap) ? -1 : n;
}

/* Verify id and signature of a received event (fields already parsed; tags_json re-serialized compactly). 0 = valid. */
static inline int nostr_event_check(const char *pubkey_hex, uint64_t created_at, int kind, const char *tags_json,
                                    const char *content, const char *id_hex, const char *sig_hex, char *work, size_t cap) {
    uint8_t pk[32], id[32], want[32], sig[64];
    if (strlen(pubkey_hex) != 64 || strlen(id_hex) != 64 || strlen(sig_hex) != 128) return -1;
    if (nvpn_hex_decode(pubkey_hex, 64, pk, 32) || nvpn_hex_decode(id_hex, 64, id, 32) || nvpn_hex_decode(sig_hex, 128, sig, 64)) return -1;
    if (nostr_event_id(pubkey_hex, created_at, kind, tags_json, content, work, cap, want)) return -1;
    if (memcmp(want, id, 32) != 0) return -2;
    return nvpn_schnorr_verify(pk, id, sig) == NVPN_OK ? 0 : -3;
}
#endif
