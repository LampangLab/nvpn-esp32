#include "fips_noise.h"
#include "fips_crypto.h"
#include "nvpn_internal.h"
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

void fips_noise_init(fips_noise_t *s, const char *proto, const uint8_t rs[32]) {
    uint8_t pre[33];
    memset(s, 0, sizeof *s);
    nvpn_sha256((const uint8_t *)proto, strlen(proto), s->h); /* name > 32 bytes -> hashed */
    memcpy(s->ck, s->h, 32);
    pre[0] = 0x02; memcpy(pre + 1, rs, 32);
    fips_noise_mix_hash(s, pre, 33);
}

void fips_noise_mix_hash(fips_noise_t *s, const uint8_t *d, size_t n) {
    nvpn_sha256_ctx c;
    nvpn_sha256_init(&c); nvpn_sha256_update(&c, s->h, 32); nvpn_sha256_update(&c, d, n); nvpn_sha256_final(&c, s->h);
}

void fips_noise_mix_key(fips_noise_t *s, const uint8_t dh[32]) {
    uint8_t ck[32];
    fips_hkdf2(s->ck, dh, 32, ck, s->k);
    memcpy(s->ck, ck, 32);
    s->n = 0; s->has_key = 1;
}

void fips_noise_encrypt_hash(fips_noise_t *s, const uint8_t *pt, size_t n, uint8_t *out) {
    fips_aead_seal(s->k, s->n++, NULL, 0, pt, n, out);
    fips_noise_mix_hash(s, out, n + 16);
}

int fips_noise_decrypt_hash(fips_noise_t *s, const uint8_t *ct, size_t n, uint8_t *out) {
    if (fips_aead_open(s->k, s->n, NULL, 0, ct, n, out) != 0) return -1;
    s->n++;
    fips_noise_mix_hash(s, ct, n);
    return 0;
}

void fips_noise_split(const fips_noise_t *s, uint8_t k1[32], uint8_t k2[32]) {
    fips_hkdf2(s->ck, NULL, 0, k1, k2);
}

static int ecdh_hash(unsigned char *out, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)y32; (void)data;
    nvpn_sha256(x32, 32, out);
    return 1;
}

int fips_ecdh(const uint8_t secret[32], const uint8_t peer33[33], uint8_t out[32]) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(nvpn_secp_ctx(), &pk, peer33, 33)) return -1;
    return secp256k1_ecdh(nvpn_secp_ctx(), out, &pk, secret, ecdh_hash, NULL) ? 0 : -1;
}

int fips_ecdh_xonly(const uint8_t secret[32], const uint8_t xonly[32], uint8_t out[32]) {
    uint8_t p[33]; p[0] = 0x02; memcpy(p + 1, xonly, 32);
    return fips_ecdh(secret, p, out);
}

int fips_gen_keypair(const fips_io_t *io, uint8_t secret[32], uint8_t pub33[33]) {
    secp256k1_pubkey pk; size_t l = 33; int tries;
    for (tries = 0; tries < 8; tries++) {
        io->random(io->ud, secret, 32);
        if (secp256k1_ec_pubkey_create(nvpn_secp_ctx(), &pk, secret)) {
            secp256k1_ec_pubkey_serialize(nvpn_secp_ctx(), pub33, &l, &pk, SECP256K1_EC_COMPRESSED);
            return 0;
        }
    }
    return -1;
}

void fips_node_addr_of(const uint8_t xonly[32], uint8_t out[16]) {
    uint8_t d[32]; nvpn_sha256(xonly, 32, d); memcpy(out, d, 16);
}

/* WireGuard-style window, 2048 entries. bit i of the bitmap = counter (highest - i). */
int fips_replay_check(const fips_replay_t *w, uint64_t c) {
    uint64_t diff;
    if (c == UINT64_MAX) return 0;
    if (c > w->highest) return 1;
    diff = w->highest - c;
    if (diff >= 2048) return 0;
    return (w->bits[diff / 64] & (1ULL << (diff % 64))) == 0;
}

void fips_replay_accept(fips_replay_t *w, uint64_t c) {
    if (c > w->highest) {
        uint64_t shift = c - w->highest;
        if (shift >= 2048) memset(w->bits, 0, sizeof w->bits);
        else {
            int word = (int)(shift / 64), bit = (int)(shift % 64), i;
            for (i = 31; i >= 0; i--) {
                uint64_t v = 0;
                if (i - word >= 0) { v = w->bits[i - word] << bit; if (bit && i - word - 1 >= 0) v |= w->bits[i - word - 1] >> (64 - bit); }
                w->bits[i] = v;
            }
        }
        w->highest = c;
        w->bits[0] |= 1;
    } else {
        uint64_t diff = w->highest - c;
        if (diff < 2048) w->bits[diff / 64] |= 1ULL << (diff % 64);
    }
}
