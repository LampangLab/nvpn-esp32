#ifndef NVPN_INTERNAL_H
#define NVPN_INTERNAL_H
#include "nvpn.h"
#include <string.h>

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t total;
    size_t fill;
} nvpn_sha256_ctx;

void nvpn_sha256_init(nvpn_sha256_ctx *c);
void nvpn_sha256_update(nvpn_sha256_ctx *c, const uint8_t *d, size_t n);
void nvpn_sha256_final(nvpn_sha256_ctx *c, uint8_t out[32]);

/* UTF-8 helper used by the JSON decoder */
size_t nvpn_utf8_encode(uint32_t cp, uint8_t *out);

#include <secp256k1.h>
secp256k1_context *nvpn_secp_ctx(void);

#endif
