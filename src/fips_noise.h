#ifndef FIPS_NOISE_H
#define FIPS_NOISE_H
#include "fips.h"

#define FIPS_PROTO_IK "Noise_IK_secp256k1_ChaChaPoly_SHA256"
#define FIPS_PROTO_XK "Noise_XK_secp256k1_ChaChaPoly_SHA256"

/* Start a handshake: h = ck = SHA256(protocol name), then mix the responder's static
 * (x-only, normalised to even parity) as the pre-message. */
void fips_noise_init(fips_noise_t *s, const char *proto, const uint8_t responder_xonly[32]);
void fips_noise_mix_hash(fips_noise_t *s, const uint8_t *d, size_t n);
void fips_noise_mix_key(fips_noise_t *s, const uint8_t dh[32]);
/* out gets n+16 bytes; mixes the ciphertext into h. */
void fips_noise_encrypt_hash(fips_noise_t *s, const uint8_t *pt, size_t n, uint8_t *out);
/* returns 0 / -1; mixes the ciphertext into h on success. */
int fips_noise_decrypt_hash(fips_noise_t *s, const uint8_t *ct, size_t n, uint8_t *out);
void fips_noise_split(const fips_noise_t *s, uint8_t k1[32], uint8_t k2[32]);

/* SHA256(x) of the ECDH point; peer is a 33-byte compressed key (parity is irrelevant for x). */
int fips_ecdh(const uint8_t secret[32], const uint8_t peer33[33], uint8_t out[32]);
int fips_ecdh_xonly(const uint8_t secret[32], const uint8_t peer_xonly[32], uint8_t out[32]);
/* random valid secret key + its compressed public key */
int fips_gen_keypair(const fips_io_t *io, uint8_t secret[32], uint8_t pub33[33]);

int fips_replay_check(const fips_replay_t *w, uint64_t ctr);
void fips_replay_accept(fips_replay_t *w, uint64_t ctr);

void fips_node_addr_of(const uint8_t xonly[32], uint8_t out[16]);
#endif
