#ifndef FIPS_INTERNAL_H
#define FIPS_INTERNAL_H
#include "fips.h"
#include "fips_noise.h"
#include "fips_crypto.h"
#include "nvpn_internal.h"

/* link layer */
int fips_link_send_msg(fips_t *f, uint8_t msg_type, const uint8_t *body, size_t blen, uint64_t now);
/* wrap payload in a SessionDatagram to dst and send over the link */
int fips_link_send_datagram(fips_t *f, const uint8_t dst[16], const uint8_t *payload, size_t plen, uint64_t now);

/* session layer (fips_session.c) */
void fips_sess_input(fips_t *f, const uint8_t src[16], const uint8_t *payload, size_t len, uint64_t now);
void fips_sess_tick(fips_t *f, uint64_t now);
void fips_sess_reset_link(fips_t *f);
void fips_build_receiver_report(const fips_session_t *s, uint64_t now, uint8_t b[66]);
void fips_trace(fips_t *f, uint8_t kind, uint8_t arg, uint64_t now);

/* mesh participation (fips_mesh.c) */
void fips_mesh_link_up(fips_t *f, uint64_t now);
void fips_mesh_on_role_msg(fips_t *f, uint8_t type, const uint8_t *b, size_t n, uint64_t now);
void fips_mesh_tick(fips_t *f, uint64_t now);
void fips_mesh_on_tree_announce(fips_t *f, const uint8_t *b, size_t n, uint64_t now);
void fips_mesh_on_lookup_request(fips_t *f, const uint8_t *b, size_t n, uint64_t now);
void fips_mesh_on_lookup_response(fips_t *f, const uint8_t *b, size_t n, uint64_t now);
const fips_coord_t *fips_coords_get(const fips_t *f, const uint8_t addr[16]);
void fips_coords_put(fips_t *f, const uint8_t addr[16], const uint8_t *raw, size_t n, int verified, uint64_t now);
size_t fips_put_coords_self(const fips_t *f, uint8_t *o);
/* writes "count(2) + coords" for a destination; returns 0 if its coordinates are unknown */
size_t fips_put_coords_of(const fips_t *f, const uint8_t addr[16], uint8_t *o);
int fips_lookup_start(fips_t *f, const uint8_t target_xonly[32], uint64_t now);
void fips_sess_coords_ready(fips_t *f, const uint8_t addr[16], uint64_t now);
void fips_sess_lookup_failed(fips_t *f, const uint8_t addr[16]);

#define FIPS_MSG_SESSION_DATAGRAM 0x00
#define FIPS_MSG_TREE_ANNOUNCE 0x10
#define FIPS_MSG_FILTER_ANNOUNCE 0x20
#define FIPS_MSG_LOOKUP_REQUEST 0x30
#define FIPS_MSG_LOOKUP_RESPONSE 0x31
#define FIPS_MSG_DISCONNECT 0x50
#define FIPS_MSG_HEARTBEAT 0x51
#define FIPS_MSG_CLIENT_ONLY 0x52
#define FIPS_MSG_CLIENT_SUPPORT 0x53

static inline void put_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void put_le32(uint8_t *p, uint32_t v) { int i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline void put_le64(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline uint16_t get_le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t get_le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t get_le64(const uint8_t *p) { return (uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32); }
#endif
