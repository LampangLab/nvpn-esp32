#ifndef FIPS_CRYPTO_H
#define FIPS_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* RFC 8439 ChaCha20-Poly1305. nonce12 = 4 zero bytes || counter LE64 (FIPS). */
void fips_aead_seal(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len, uint8_t *out /* pt_len + 16 */);
/* Returns 0 on success, -1 on authentication failure. out may equal ct. */
int fips_aead_open(const uint8_t key[32], uint64_t counter, const uint8_t *aad, size_t aad_len,
                   const uint8_t *ct, size_t ct_len /* incl. tag */, uint8_t *out);

void fips_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]);
/* HKDF-SHA256(salt, ikm, info="") -> 64 bytes (what Noise MixKey/Split use). */
void fips_hkdf2(const uint8_t salt[32], const uint8_t *ikm, size_t ilen, uint8_t out1[32], uint8_t out2[32]);
#endif
