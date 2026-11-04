/* FMP link layer: Noise IK initiator + established frames. */
#include "fips_internal.h"
#include <secp256k1_extrakeys.h>

#define HS1_NOISE 106
#define HS2_NOISE 57

int fips_init(fips_t *f, const fips_io_t *io, const uint8_t secret[32], const uint8_t upstream_xonly[32]) {
    secp256k1_pubkey pk; size_t l = 33;
    if (!f || !io || !io->send || !io->random || !secret || !upstream_xonly) return FIPS_ERR_ARG;
    memset(f, 0, sizeof *f);
    f->io = *io;
    memcpy(f->secret, secret, 32);
    if (!secp256k1_ec_pubkey_create(nvpn_secp_ctx(), &pk, secret)) return FIPS_ERR_CRYPTO;
    secp256k1_ec_pubkey_serialize(nvpn_secp_ctx(), f->pub_comp, &l, &pk, SECP256K1_EC_COMPRESSED);
    memcpy(f->pub_xonly, f->pub_comp + 1, 32);
    fips_node_addr_of(f->pub_xonly, f->node_addr);
    io->random(io->ud, f->epoch, 8);
    memcpy(f->upstream_xonly, upstream_xonly, 32);
    fips_node_addr_of(upstream_xonly, f->upstream_addr);
    f->heartbeat_ms = 5000;
    f->dead_ms = 30000;
    return FIPS_OK;
}

const uint8_t *fips_node_addr(const fips_t *f) { return f->node_addr; }
int fips_link_state(const fips_t *f) { return f->link.state; }

void fips_ipv6_addr(const uint8_t a[16], uint8_t out[16]) { out[0] = 0xfd; memcpy(out + 1, a, 15); }

void fips_trace(fips_t *f, uint8_t kind, uint8_t arg, uint64_t now) {
    fips_trace_t *e = &f->trace[f->trace_n % FIPS_TRACE_N];
    e->t_ms = (uint32_t)now; e->tx = f->n_tx; e->rx = f->n_rx; e->kind = kind; e->arg = arg;
    f->trace_n++;
}

int fips_trace_get(const fips_t *f, uint32_t i, fips_trace_t *out) {
    if (i >= f->trace_n || f->trace_n - i > FIPS_TRACE_N) return 0;
    *out = f->trace[i % FIPS_TRACE_N];
    return 1;
}

static void link_down(fips_t *f, uint64_t now) {
    if (f->link.state == FIPS_LINK_UP) fips_trace(f, FIPS_TR_LINK_DOWN, 0, now);
    f->link.state = FIPS_LINK_DOWN;
    f->link.t_down_ms = now;
    memset(f->link.send_key, 0, 32); memset(f->link.recv_key, 0, 32);
    fips_sess_reset_link(f);
}

int fips_connect(fips_t *f, uint64_t now) {
    fips_link_t *l; uint8_t e_pub[33], dh[32], *m;
    if (!f) return FIPS_ERR_ARG;
    l = &f->link;
    memset(l, 0, sizeof *l);
    l->want_up = 1;
    do { f->io.random(f->io.ud, (uint8_t *)&l->our_idx, 4); } while (l->our_idx == 0);

    fips_noise_init(&l->hs, FIPS_PROTO_IK, f->upstream_xonly);
    if (fips_gen_keypair(&f->io, l->e_secret, e_pub)) return FIPS_ERR_CRYPTO;

    m = l->msg1;
    m[0] = 0x01; m[1] = 0; put_le16(m + 2, 4 + HS1_NOISE); put_le32(m + 4, l->our_idx);
    memcpy(m + 8, e_pub, 33);
    fips_noise_mix_hash(&l->hs, e_pub, 33);                                   /* -> e  */
    if (fips_ecdh_xonly(l->e_secret, f->upstream_xonly, dh)) return FIPS_ERR_CRYPTO; /* es */
    fips_noise_mix_key(&l->hs, dh);
    fips_noise_encrypt_hash(&l->hs, f->pub_comp, 33, m + 8 + 33);             /* -> s  */
    if (fips_ecdh_xonly(f->secret, f->upstream_xonly, dh)) return FIPS_ERR_CRYPTO;  /* ss */
    fips_noise_mix_key(&l->hs, dh);
    fips_noise_encrypt_hash(&l->hs, f->epoch, 8, m + 8 + 33 + 49);            /* epoch */

    l->state = FIPS_LINK_HANDSHAKING;
    l->t_hs_start_ms = l->t_msg1_ms = now;
    f->io.send(f->io.ud, l->msg1, sizeof l->msg1);
    return FIPS_OK;
}

static int handle_msg2(fips_t *f, const uint8_t *d, size_t n, uint64_t now) {
    fips_link_t *l = &f->link; fips_noise_t hs; uint8_t dh[32], epoch[8], k1[32], k2[32];
    const uint8_t *noise;
    if (l->state != FIPS_LINK_HANDSHAKING) return FIPS_ERR_STATE;
    if (n != 69 || get_le16(d + 2) != 65) return FIPS_ERR_PARSE;
    if (get_le32(d + 8) != l->our_idx) return FIPS_ERR_PARSE;
    noise = d + 12;
    hs = l->hs;                                  /* work on a copy: a forged msg2 must not wreck the handshake */
    fips_noise_mix_hash(&hs, noise, 33);                                      /* <- e  */
    if (fips_ecdh(l->e_secret, noise, dh)) return FIPS_ERR_CRYPTO;            /* ee */
    fips_noise_mix_key(&hs, dh);
    if (fips_ecdh_xonly(l->e_secret, f->upstream_xonly, dh)) return FIPS_ERR_CRYPTO; /* es (again) */
    fips_noise_mix_key(&hs, dh);
    if (fips_noise_decrypt_hash(&hs, noise + 33, 24, epoch)) return FIPS_ERR_AUTH;
    fips_noise_split(&hs, k1, k2);
    memcpy(l->send_key, k1, 32); memcpy(l->recv_key, k2, 32);                 /* initiator: send=k1 */
    memcpy(l->peer_epoch, epoch, 8);
    l->their_idx = get_le32(d + 4);
    memset(l->e_secret, 0, 32); memset(&l->hs, 0, sizeof l->hs);
    l->send_ctr = 0; memset(&l->replay, 0, sizeof l->replay);
    l->state = FIPS_LINK_UP;
    f->k_seen_valid = 0; fips_trace(f, FIPS_TR_LINK_UP, 0, now);
    l->t_start_ms = l->t_last_rx_ms = l->t_last_tx_ms = now;
    fips_mesh_link_up(f, now);
    fips_link_send_msg(f, FIPS_MSG_HEARTBEAT, NULL, 0, now);                  /* tell the peer we're up */
    return FIPS_OK;
}

int fips_link_send_msg(fips_t *f, uint8_t type, const uint8_t *body, size_t blen, uint64_t now) {
    fips_link_t *l = &f->link; uint8_t *p = f->tx; size_t plen = 5 + blen;
    if (l->state != FIPS_LINK_UP) return FIPS_ERR_STATE;
    if (16 + plen + 16 > sizeof f->tx) return FIPS_ERR_TOOBIG;
    if (l->send_ctr == UINT64_MAX) return FIPS_ERR_STATE;
    p[0] = 0x00; p[1] = 0; put_le16(p + 2, (uint16_t)plen); put_le32(p + 4, l->their_idx); put_le64(p + 8, l->send_ctr);
    put_le32(f->pt, (uint32_t)(now - l->t_start_ms)); f->pt[4] = type;
    if (blen) memcpy(f->pt + 5, body, blen);
    fips_aead_seal(l->send_key, l->send_ctr++, p, 16, f->pt, plen, p + 16);
    f->io.send(f->io.ud, p, 16 + plen + 16);
    l->t_last_tx_ms = now;
    f->n_tx++;
    return FIPS_OK;
}

int fips_link_send_datagram(fips_t *f, const uint8_t dst[16], const uint8_t *payload, size_t plen, uint64_t now) {
    uint8_t buf[FIPS_MTU];
    if (plen + 35 > sizeof buf - 64) return FIPS_ERR_TOOBIG;
    buf[0] = 64;                      /* ttl */
    put_le16(buf + 1, 0xffff);        /* path_mtu */
    memcpy(buf + 3, f->node_addr, 16);
    memcpy(buf + 19, dst, 16);
    memcpy(buf + 35, payload, plen);
    return fips_link_send_msg(f, FIPS_MSG_SESSION_DATAGRAM, buf, 35 + plen, now);
}

static int handle_established(fips_t *f, const uint8_t *d, size_t n, uint64_t now) {
    fips_link_t *l = &f->link; uint64_t ctr; size_t plen; uint8_t type;
    if (l->state != FIPS_LINK_UP || n < 32) return FIPS_ERR_STATE;
    if (get_le32(d + 4) != l->our_idx) return FIPS_ERR_PARSE;
    ctr = get_le64(d + 8);
    if (!fips_replay_check(&l->replay, ctr)) return FIPS_ERR_REPLAY;
    plen = n - 32;
    if (get_le16(d + 2) != plen) return FIPS_ERR_PARSE;
    if (fips_aead_open(l->recv_key, ctr, d, 16, d + 16, n - 16, f->pt)) return FIPS_ERR_AUTH;
    fips_replay_accept(&l->replay, ctr);
    l->t_last_rx_ms = now;
    f->n_rx++;
    {   uint8_t K = d[1] & 1;                                                  /* FMP key-epoch flag: flips when the link rekeys */
        if (f->k_seen_valid && K != f->k_seen) fips_trace(f, FIPS_TR_FMP_KFLIP, K, now);
        f->k_seen = K; f->k_seen_valid = 1; }
    if (plen < 5) return FIPS_ERR_PARSE;
    type = f->pt[4];
    switch (type) {
    case FIPS_MSG_SESSION_DATAGRAM:
        if (plen >= 5 + 35 && memcmp(f->pt + 5 + 19, f->node_addr, 16) == 0) {
            f->diag[FIPS_DG_TO_US]++;
            fips_sess_input(f, f->pt + 5 + 3, f->pt + 5 + 35, plen - 5 - 35, now);
        } else f->diag[FIPS_DG_OTHER]++;
        break;
    case FIPS_MSG_TREE_ANNOUNCE: fips_mesh_on_tree_announce(f, f->pt + 5, plen - 5, now); break;
    case FIPS_MSG_LOOKUP_REQUEST: fips_mesh_on_lookup_request(f, f->pt + 5, plen - 5, now); break;
    case FIPS_MSG_LOOKUP_RESPONSE: fips_mesh_on_lookup_response(f, f->pt + 5, plen - 5, now); break;
    case FIPS_MSG_CLIENT_SUPPORT:
    case FIPS_MSG_CLIENT_ONLY: fips_mesh_on_role_msg(f, type, f->pt + 5, plen - 5, now); break;
    case FIPS_MSG_DISCONNECT: link_down(f, now); break;
    default: break; /* heartbeat, filter announce, MMP reports: ignored by a leaf */
    }
    return FIPS_OK;
}

int fips_input(fips_t *f, const uint8_t *d, size_t n, uint64_t now) {
    if (!f || !d || n < 4) return FIPS_ERR_ARG;
    if ((d[0] >> 4) != 0) return FIPS_ERR_PARSE;
    switch (d[0] & 15) {
    case 2: return handle_msg2(f, d, n, now);
    case 0: return handle_established(f, d, n, now);
    case 1: if (f->link.state == FIPS_LINK_UP) fips_trace(f, FIPS_TR_FMP_MSG1_RX, 0, now); return FIPS_ERR_PARSE; /* msg1: we are never a responder (unauthenticated, counted only) */
    default: return FIPS_ERR_PARSE;
    }
}

void fips_disconnect(fips_t *f, uint64_t now) {
    uint8_t reason = 0x00;
    if (f->link.state == FIPS_LINK_UP) fips_link_send_msg(f, FIPS_MSG_DISCONNECT, &reason, 1, now);
    f->link.want_up = 0;
    link_down(f, now);
}

void fips_tick(fips_t *f, uint64_t now) {
    fips_link_t *l = &f->link;
    switch (l->state) {
    case FIPS_LINK_HANDSHAKING: {
        uint64_t backoff = 1000ULL << (l->resends > 4 ? 4 : l->resends);
        if (now - l->t_hs_start_ms >= 30000) { link_down(f, now); break; }
        if (now - l->t_msg1_ms >= backoff) { l->resends++; l->t_msg1_ms = now; f->io.send(f->io.ud, l->msg1, sizeof l->msg1); }
        break;
    }
    case FIPS_LINK_UP:
        if (now - l->t_last_rx_ms > f->dead_ms) { link_down(f, now); break; }
        if (now - l->t_last_tx_ms >= f->heartbeat_ms) fips_link_send_msg(f, FIPS_MSG_HEARTBEAT, NULL, 0, now);
        fips_mesh_tick(f, now);
        fips_sess_tick(f, now);
        break;
    default:
        if (l->want_up && now - l->t_down_ms >= 5000) fips_connect(f, now);
        break;
    }
}
