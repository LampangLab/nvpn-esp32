#include "fips_crypto.h"
#include "nvpn.h"
#include "crypto_vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)
static size_t unhex(const char *h, uint8_t *o) { size_t n = strlen(h) / 2; if (n) nvpn_hex_decode(h, n * 2, o, n); return n; }
int main(void) {
    size_t i;
    for (i = 0; i < sizeof V_AEAD / sizeof *V_AEAD; i++) {
        uint8_t key[32], aad[64], pt[1500], ct[1520], out[1520]; size_t al, pl, cl;
        unhex(V_AEAD[i].key, key); al = unhex(V_AEAD[i].aad, aad); pl = unhex(V_AEAD[i].pt, pt); cl = unhex(V_AEAD[i].ct, ct);
        fips_aead_seal(key, V_AEAD[i].ctr, aad, al, pt, pl, out);
        CHECK(cl == pl + 16 && !memcmp(out, ct, cl), "seal vector %zu (pt %zu aad %zu)", i, pl, al);
        CHECK(fips_aead_open(key, V_AEAD[i].ctr, aad, al, ct, cl, out) == 0 && !memcmp(out, pt, pl), "open vector %zu", i);
        ct[cl - 1] ^= 1; CHECK(fips_aead_open(key, V_AEAD[i].ctr, aad, al, ct, cl, out) != 0, "tampered tag accepted %zu", i);
        ct[cl - 1] ^= 1; if (al) { aad[0] ^= 1; CHECK(fips_aead_open(key, V_AEAD[i].ctr, aad, al, ct, cl, out) != 0, "tampered aad accepted %zu", i); }
        /* in-place open */
        { uint8_t buf[1520]; memcpy(buf, ct, cl); if (al) aad[0] ^= 1; CHECK(fips_aead_open(key, V_AEAD[i].ctr, aad, al, buf, cl, buf) == 0 && !memcmp(buf, pt, pl), "in-place open %zu", i); }
    }
    for (i = 0; i < sizeof V_HMAC / sizeof *V_HMAC; i++) {
        uint8_t key[200], msg[300], mac[32], got[32]; size_t kl = unhex(V_HMAC[i].key, key), ml = unhex(V_HMAC[i].msg, msg);
        unhex(V_HMAC[i].mac, mac); fips_hmac_sha256(key, kl, msg, ml, got);
        CHECK(!memcmp(got, mac, 32), "hmac %zu", i);
    }
    for (i = 0; i < sizeof V_HKDF / sizeof *V_HKDF; i++) {
        uint8_t salt[32], ikm[40], okm[64], a[32], b[32]; size_t il;
        unhex(V_HKDF[i].salt, salt); il = unhex(V_HKDF[i].ikm, ikm); unhex(V_HKDF[i].okm, okm);
        fips_hkdf2(salt, ikm, il, a, b);
        CHECK(!memcmp(a, okm, 32) && !memcmp(b, okm + 32, 32), "hkdf %zu", i);
    }
    printf("%d checks, %d failures\n", checks, fails);
    return fails != 0;
}
