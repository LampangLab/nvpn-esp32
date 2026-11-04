#include "nvpn_internal.h"
#include <stddef.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_schnorrsig.h>

/* ---------------------------------------------------------------- hex --- */

void nvpn_hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) { out[2 * i] = hx[in[i] >> 4]; out[2 * i + 1] = hx[in[i] & 15]; }
    out[2 * len] = 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int nvpn_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len) {
    size_t i;
    if (!hex || !out || hex_len != out_len * 2) return NVPN_ERR_ARG;
    for (i = 0; i < out_len; i++) {
        int a = hexval(hex[2 * i]), b = hexval(hex[2 * i + 1]);
        if (a < 0 || b < 0) return NVPN_ERR_ARG;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return NVPN_OK;
}

/* ------------------------------------------------------------- bech32 --- */

static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t b32_polymod(const uint8_t *v, size_t n) {
    static const uint32_t G[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    size_t i;
    int j;
    for (i = 0; i < n; i++) {
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ v[i];
        for (j = 0; j < 5; j++) if ((top >> j) & 1) chk ^= G[j];
    }
    return chk;
}

/* Convert 8-bit groups <-> 5-bit groups. Returns output length or -1. */
static int convert_bits(const uint8_t *in, size_t n, int from, int to, int pad, uint8_t *out, size_t cap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0, i;
    uint32_t maxv = (1u << to) - 1;
    for (i = 0; i < n; i++) {
        acc = (acc << from) | in[i];
        bits += from;
        while (bits >= to) {
            bits -= to;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
        acc &= (1u << bits) - 1; /* keep only pending bits; avoids overflow */
    }
    if (pad) {
        if (bits) { if (o >= cap) return -1; out[o++] = (uint8_t)((acc << (to - bits)) & maxv); }
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
        return -1;
    }
    return (int)o;
}

int nvpn_pubkey_to_npub(const uint8_t pk[NVPN_PUBKEY_LEN], char *out, size_t out_cap) {
    uint8_t d5[52], chk_in[4 + 1 + 4 + 52 + 6];
    uint32_t pm;
    size_t i, n = 0;
    int k;
    if (!pk || !out || out_cap < 64) return NVPN_ERR_BUF;
    k = convert_bits(pk, 32, 8, 5, 1, d5, sizeof d5);
    if (k != 52) return NVPN_ERR_ARG;
    /* hrp expand("npub") = high bits, 0, low bits */
    for (i = 0; i < 4; i++) chk_in[n++] = (uint8_t)("npub"[i] >> 5);
    chk_in[n++] = 0;
    for (i = 0; i < 4; i++) chk_in[n++] = (uint8_t)("npub"[i] & 31);
    /* layout: [hi x4][0][lo x4][data x52][0 x6] */
    memcpy(chk_in + 9, d5, 52);
    memset(chk_in + 9 + 52, 0, 6);
    pm = b32_polymod(chk_in, 9 + 52 + 6) ^ 1;
    memcpy(out, "npub1", 5);
    for (i = 0; i < 52; i++) out[5 + i] = B32[d5[i]];
    for (i = 0; i < 6; i++) out[57 + i] = B32[(pm >> (5 * (5 - i))) & 31];
    out[63] = 0;
    return NVPN_OK;
}

static int npub_decode(const char *s, uint8_t out[32]) {
    size_t n = strlen(s), i;
    uint8_t v[9 + 52 + 6], d5[52];
    int lower = 0, upper = 0;
    uint32_t pm;
    if (n != 63) return NVPN_ERR_ARG;
    for (i = 0; i < n; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') lower = 1;
        if (s[i] >= 'A' && s[i] <= 'Z') upper = 1;
    }
    if (lower && upper) return NVPN_ERR_ARG;
    for (i = 0; i < 4; i++) {
        char c = s[i] | 0x20;
        if (c != "npub"[i]) return NVPN_ERR_ARG;
        v[i] = (uint8_t)(c >> 5);
        v[5 + i] = (uint8_t)(c & 31);
    }
    if ((s[4]) != '1') return NVPN_ERR_ARG;
    v[4] = 0;
    for (i = 0; i < 58; i++) {
        char c = s[5 + i];
        const char *p;
        if (c >= 'A' && c <= 'Z') c = (char)(c | 0x20);
        p = memchr(B32, c, 32);
        if (!p || c == 0) return NVPN_ERR_ARG;
        v[9 + i] = (uint8_t)(p - B32);
    }
    pm = b32_polymod(v, sizeof v);
    if (pm != 1) return NVPN_ERR_ARG;
    memcpy(d5, v + 9, 52);
    if (convert_bits(d5, 52, 5, 8, 0, out, 32) != 32) return NVPN_ERR_ARG;
    return NVPN_OK;
}

int nvpn_pubkey_parse(const char *s, uint8_t out[NVPN_PUBKEY_LEN]) {
    size_t n;
    if (!s || !out) return NVPN_ERR_ARG;
    n = strlen(s);
    if (n == 64) return nvpn_hex_decode(s, 64, out, 32) == NVPN_OK ? NVPN_OK : NVPN_ERR_PUBKEY;
    if (n == 63) return npub_decode(s, out) == NVPN_OK ? NVPN_OK : NVPN_ERR_PUBKEY;
    return NVPN_ERR_PUBKEY;
}

/* ----------------------------------------------------------- secp256k1 --- */

/* libsecp256k1 is built with USE_EXTERNAL_DEFAULT_CALLBACKS (no stdio). An
 * illegal argument just makes the call fail; an internal inconsistency aborts. */
#include <stdlib.h>
void secp256k1_default_illegal_callback_fn(const char *str, void *data) { (void)str; (void)data; }
void secp256k1_default_error_callback_fn(const char *str, void *data) { (void)str; (void)data; abort(); }

/* The context lives in static storage (no heap). Tables are compile-time
 * constants, so the context itself is tiny. */
#ifndef NVPN_SECP_CTX_BYTES
#define NVPN_SECP_CTX_BYTES 1024
#endif
static union { max_align_t a; uint8_t b[NVPN_SECP_CTX_BYTES]; } g_ctx_mem;
static secp256k1_context *g_ctx;

secp256k1_context *nvpn_secp_ctx(void) {
    if (!g_ctx) {
        if (secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) > sizeof g_ctx_mem) return NULL;
        g_ctx = secp256k1_context_preallocated_create(g_ctx_mem.b, SECP256K1_CONTEXT_NONE);
    }
    return g_ctx;
}

int nvpn_secp_randomize(const uint8_t seed32[32]) {
    if (!nvpn_secp_ctx()) return NVPN_ERR_ARG;
    return secp256k1_context_randomize(nvpn_secp_ctx(), seed32) ? NVPN_OK : NVPN_ERR_ARG;
}

int nvpn_pubkey_from_secret(const uint8_t secret[32], uint8_t pk_out[NVPN_PUBKEY_LEN]) {
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xp;
    if (!secret || !pk_out || !nvpn_secp_ctx()) return NVPN_ERR_ARG;
    if (!secp256k1_keypair_create(nvpn_secp_ctx(), &kp, secret)) return NVPN_ERR_ARG;
    if (!secp256k1_keypair_xonly_pub(nvpn_secp_ctx(), &xp, NULL, &kp)) return NVPN_ERR_ARG;
    secp256k1_xonly_pubkey_serialize(nvpn_secp_ctx(), pk_out, &xp);
    return NVPN_OK;
}

int nvpn_schnorr_sign(const uint8_t secret[32], const uint8_t msg32[32], const uint8_t *aux32, uint8_t sig_out[64]) {
    secp256k1_keypair kp;
    if (!secret || !msg32 || !sig_out || !nvpn_secp_ctx()) return NVPN_ERR_ARG;
    if (!secp256k1_keypair_create(nvpn_secp_ctx(), &kp, secret)) return NVPN_ERR_ARG;
    return secp256k1_schnorrsig_sign32(nvpn_secp_ctx(), sig_out, msg32, &kp, aux32) ? NVPN_OK : NVPN_ERR_ARG;
}

int nvpn_schnorr_verify(const uint8_t pk[NVPN_PUBKEY_LEN], const uint8_t msg32[32], const uint8_t sig[64]) {
    secp256k1_xonly_pubkey xp;
    if (!pk || !msg32 || !sig || !nvpn_secp_ctx()) return NVPN_ERR_ARG;
    if (!secp256k1_xonly_pubkey_parse(nvpn_secp_ctx(), &xp, pk)) return NVPN_ERR_PUBKEY;
    return secp256k1_schnorrsig_verify(nvpn_secp_ctx(), sig, msg32, 32, &xp) ? NVPN_OK : NVPN_ERR_SIG;
}

/* --------------------------------------------------- network id / tunnel --- */

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

int nvpn_normalize_network_id(const char *in, char *out, size_t out_cap) {
    const char *b, *e;
    size_t i, o = 0;
    int all_hex = 1, any = 0;
    if (!in || !out || out_cap == 0) return NVPN_ERR_ARG;
    b = in; e = in + strlen(in);
    while (b < e && is_ws(*b)) b++;
    while (e > b && is_ws(e[-1])) e--;
    if ((size_t)(e - b) >= 10 && memcmp(b, "nostr-vpn:", 10) == 0) b += 10;
    while (b < e && is_ws(*b)) b++;
    while (e > b && is_ws(e[-1])) e--;
    for (i = 0; b + i < e; i++) {
        char c = b[i];
        if (is_ws(c) || c == '-') continue;
        any = 1;
        if (hexval(c) < 0) all_hex = 0;
    }
    if (!any) { out[0] = 0; return 0; }
    if (all_hex) {
        for (i = 0; b + i < e; i++) {
            char c = b[i];
            if (is_ws(c) || c == '-') continue;
            if (o + 1 >= out_cap) return NVPN_ERR_BUF;
            out[o++] = (c >= 'A' && c <= 'F') ? (char)(c + 32) : c;
        }
    } else {
        if ((size_t)(e - b) + 1 > out_cap) return NVPN_ERR_BUF;
        memcpy(out, b, (size_t)(e - b));
        o = (size_t)(e - b);
    }
    out[o] = 0;
    return (int)o;
}

int nvpn_derive_tunnel_ip(const char *network_id, const uint8_t pk[NVPN_PUBKEY_LEN], uint8_t ip_out[4]) {
    char nid[NVPN_MAX_NETID + 1 + 8], hex[65];
    uint8_t d[32];
    nvpn_sha256_ctx c;
    int n;
    if (!network_id || !pk || !ip_out) return NVPN_ERR_ARG;
    n = nvpn_normalize_network_id(network_id, nid, sizeof nid);
    if (n <= 0) return NVPN_ERR_ARG;
    nvpn_hex_encode(pk, 32, hex);
    nvpn_sha256_init(&c);
    nvpn_sha256_update(&c, (const uint8_t *)nid, (size_t)n);
    nvpn_sha256_update(&c, (const uint8_t *)"\n", 1);
    nvpn_sha256_update(&c, (const uint8_t *)hex, 64);
    nvpn_sha256_final(&c, d);
    ip_out[0] = 10; ip_out[1] = 44;
    ip_out[2] = (uint8_t)(d[0] % 254 + 1);
    ip_out[3] = (uint8_t)(d[1] % 254 + 1);
    return NVPN_OK;
}
