/* On-device self-test (no network needed). Shared by the Arduino sketch and the host runner.
 * Known-answer tests for hashing, secp256k1/BIP-340, ECDH and ChaCha20-Poly1305, plus timings. */
#ifndef SELFTEST_CORE_H
#define SELFTEST_CORE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>
#include "nvpn.h"
#include "fips_crypto.h"
#include "fips_noise.h"
#ifdef __cplusplus
}
#endif

typedef struct { void (*log)(const char *); unsigned long (*micros_fn)(void); int pass, fail; } st_t;

static void st_check(st_t *t, const char *name, int ok) {
    char b[96];
    if (ok) t->pass++; else t->fail++;
    snprintf(b, sizeof b, "[%s] %s", ok ? "PASS" : "FAIL", name);
    t->log(b);
}
static void st_hex(const uint8_t *p, size_t n, char *o) { nvpn_hex_encode(p, n, o); }
static int st_eqhex(const uint8_t *p, size_t n, const char *hex) { char o[129]; st_hex(p, n, o); return strcmp(o, hex) == 0; }

static void st_time(st_t *t, const char *name, unsigned long t0) {
    char b[96];
    snprintf(b, sizeof b, "      %s: %lu us", name, t->micros_fn() - t0);
    t->log(b);
}

static int selftest_run(st_t *t) {
    uint8_t sk[32] = {0}, pk[32], msg[32] = {0}, aux[32] = {0}, sig[64], h[32], sk2[32] = {0}, pk2[32], e1[32], e2[32];
    uint8_t key[32], ct[64], pt[32], out[32];
    unsigned long t0;
    int i;
    t->pass = t->fail = 0;

    nvpn_sha256((const uint8_t *)"abc", 3, h);
    st_check(t, "sha256(\"abc\")", st_eqhex(h, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    sk[31] = 1;
    t0 = t->micros_fn();
    int rc = nvpn_pubkey_from_secret(sk, pk);
    st_time(t, "pubkey_from_secret", t0);
    st_check(t, "pubkey(1) = generator x", rc == NVPN_OK && st_eqhex(pk, 32, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));

    /* BIP-340 test vector 0 */
    memset(sk, 0, 32); sk[31] = 3;
    nvpn_pubkey_from_secret(sk, pk);
    st_check(t, "BIP340 vec0 pubkey", st_eqhex(pk, 32, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"));
    t0 = t->micros_fn();
    rc = nvpn_schnorr_sign(sk, msg, aux, sig);
    st_time(t, "schnorr_sign", t0);
    st_check(t, "BIP340 vec0 signature", rc == NVPN_OK && st_eqhex(sig, 64,
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"));
    t0 = t->micros_fn();
    rc = nvpn_schnorr_verify(pk, msg, sig);
    st_time(t, "schnorr_verify", t0);
    st_check(t, "schnorr verify ok", rc == NVPN_OK);
    sig[10] ^= 1;
    st_check(t, "schnorr verify rejects tampered sig", nvpn_schnorr_verify(pk, msg, sig) != NVPN_OK);

    /* ECDH symmetry (x-only hashing) */
    memset(sk, 0, 32); sk[31] = 5; memset(sk2, 0, 32); sk2[31] = 7;
    nvpn_pubkey_from_secret(sk, pk); nvpn_pubkey_from_secret(sk2, pk2);
    t0 = t->micros_fn();
    rc = fips_ecdh_xonly(sk, pk2, e1);
    st_time(t, "ecdh", t0);
    st_check(t, "ecdh a*B == b*A", rc == 0 && fips_ecdh_xonly(sk2, pk, e2) == 0 && memcmp(e1, e2, 32) == 0);

    /* ChaCha20-Poly1305 roundtrip, counter binding, tamper detection */
    for (i = 0; i < 32; i++) { key[i] = (uint8_t)i; pt[i] = (uint8_t)(0xa0 + i); }
    fips_aead_seal(key, 42, (const uint8_t *)"hdr", 3, pt, 32, ct);
    st_check(t, "aead roundtrip", fips_aead_open(key, 42, (const uint8_t *)"hdr", 3, ct, 32 + 16, out) == 0 && memcmp(out, pt, 32) == 0);
    st_check(t, "aead wrong counter rejected", fips_aead_open(key, 43, (const uint8_t *)"hdr", 3, ct, 32 + 16, out) != 0);
    st_check(t, "aead wrong aad rejected", fips_aead_open(key, 42, (const uint8_t *)"hdx", 3, ct, 32 + 16, out) != 0);
    ct[5] ^= 1;
    st_check(t, "aead tampered ct rejected", fips_aead_open(key, 42, (const uint8_t *)"hdr", 3, ct, 32 + 16, out) != 0);

    /* mesh IP derivation: always 10.44.x.y with x,y in 1..254 */
    {
        uint8_t ip[4];
        rc = nvpn_derive_tunnel_ip("test-net", pk, ip);
        st_check(t, "tunnel ip in 10.44/16", rc == NVPN_OK && ip[0] == 10 && ip[1] == 44 && ip[2] >= 1 && ip[2] <= 254 && ip[3] >= 1 && ip[3] <= 254);
    }
    {
        char b[64];
        snprintf(b, sizeof b, "RESULT: %d passed, %d failed", t->pass, t->fail);
        t->log(b);
    }
    return t->fail;
}
#endif
