/* FSP: end-to-end Noise XK sessions (initiator and responder), port datagrams and EndpointData packets. */
#include "fips_internal.h"

#define S_FREE 0
#define S_AWAIT_ACK 1
#define S_UP 2
#define S_AWAIT_MSG3 3
#define S_LOOKUP 4
#define WARM_PACKETS 5
#define COORDS_RESP_INTERVAL_MS 2000
#define LOOKUP_WAIT_MS 20000
#define DEAD_PEER_MS 20000        /* sending without ever hearing back for this long: the peer lost the session (restart) */
#define DEAD_PEER_MIN_PKTS 3
#define RR_MIN_MS 1000            /* at most one ReceiverReport per second per session */
#define FSP_DRAIN_MS 45000        /* keep the previous epoch's receive key this long after a rekey cutover */
#define XK_MSG1 33
#define XK_MSG2 57
#define XK_MSG3 73
#define MSG3_WAIT_MS 10000

static fips_session_t *find_state(fips_t *f, const uint8_t addr[16], int state) {
    int i;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++)
        if (f->sess[i].state == state && memcmp(f->sess[i].peer_addr, addr, 16) == 0) return &f->sess[i];
    return NULL;
}
/* Established session if there is one, else any pending one. */
static fips_session_t *find(fips_t *f, const uint8_t addr[16]) {
    fips_session_t *s = find_state(f, addr, S_UP);
    if (!s) s = find_state(f, addr, S_AWAIT_ACK);
    if (!s) s = find_state(f, addr, S_AWAIT_MSG3);
    if (!s) s = find_state(f, addr, S_LOOKUP);
    return s;
}

static fips_session_t *alloc_slot(fips_t *f) {
    int i, best = -1;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++) if (f->sess[i].state == S_FREE) return &f->sess[i];
    for (i = 0; i < FIPS_MAX_SESSIONS; i++)                     /* evict the least recently used */
        if (best < 0 || f->sess[i].t_used_ms < f->sess[best].t_used_ms) best = i;
    memset(&f->sess[best], 0, sizeof f->sess[best]);
    return &f->sess[best];
}

static size_t put_coords_self(const fips_t *f, uint8_t *o) { return fips_put_coords_self(f, o); }

static size_t put_coords_dest(const fips_t *f, const fips_session_t *s, uint8_t *o) {
    size_t n = fips_put_coords_of(f, s->peer_addr, o);
    return n ? n : put_coords_self(f, o); /* same fallback as the reference initiator for an unknown destination */
}

static int build_setup(fips_t *f, fips_session_t *s, const uint8_t msg1[XK_MSG1]) {
    uint8_t *p = s->setup_pkt; size_t o = 4;
    p[0] = 0x01; p[1] = 0;
    p[o++] = 0x00;                                   /* session flags */
    o += put_coords_self(f, p + o);
    if (o + 2 + 16 * 17 + 2 + XK_MSG1 > sizeof s->setup_pkt) return FIPS_ERR_TOOBIG;
    o += put_coords_dest(f, s, p + o);
    if (o + 2 + XK_MSG1 > sizeof s->setup_pkt) return FIPS_ERR_TOOBIG;
    put_le16(p + o, XK_MSG1); o += 2;
    memcpy(p + o, msg1, XK_MSG1); o += XK_MSG1;
    put_le16(p + 2, (uint16_t)(o - 4));
    s->setup_len = o;
    return FIPS_OK;
}

/* Send the Noise XK first message as a SessionSetup (coordinates must be known by now). */
static int start_setup(fips_t *f, fips_session_t *s, uint64_t now) {
    uint8_t e_pub[33], dh[32]; int rc;
    fips_noise_init(&s->hs, FIPS_PROTO_XK, s->peer_xonly);
    if (fips_gen_keypair(&f->io, s->e_secret, e_pub)) return FIPS_ERR_CRYPTO;
    fips_noise_mix_hash(&s->hs, e_pub, 33);                                 /* -> e  */
    if (fips_ecdh_xonly(s->e_secret, s->peer_xonly, dh)) return FIPS_ERR_CRYPTO;
    fips_noise_mix_key(&s->hs, dh);                                         /* -> es */
    if ((rc = build_setup(f, s, e_pub))) return rc;
    s->state = S_AWAIT_ACK; s->resends = 0; s->t_setup_ms = s->t_used_ms = now;
    fips_link_send_datagram(f, s->peer_addr, s->setup_pkt, s->setup_len, now);
    return FIPS_OK;
}

int fips_session_open(fips_t *f, const uint8_t dest[32], uint64_t now) {
    fips_session_t *s = NULL; uint8_t addr[16], tmp[2 + 16 * FIPS_MAX_DEPTH]; int rc;
    if (!f || !dest) return FIPS_ERR_ARG;
    if (f->link.state != FIPS_LINK_UP) return FIPS_ERR_STATE;
    fips_node_addr_of(dest, addr);
    if ((s = find(f, addr))) return (int)(s - f->sess);
    s = alloc_slot(f);
    memset(s, 0, sizeof *s);
    memcpy(s->peer_xonly, dest, 32); memcpy(s->peer_addr, addr, 16);
    if (fips_put_coords_of(f, addr, tmp)) {                                 /* the upstream itself, or already cached */
        if ((rc = start_setup(f, s, now))) { memset(s, 0, sizeof *s); return rc; }
    } else {                                                                /* multi-hop: find the destination's coordinates first */
        s->state = S_LOOKUP; s->t_setup_ms = s->t_used_ms = now;
        if ((rc = fips_lookup_start(f, dest, now))) { memset(s, 0, sizeof *s); return rc; }
    }
    return (int)(s - f->sess);
}

/* lookup answered: start waiting setups, and re-warm established sessions to that destination */
void fips_sess_coords_ready(fips_t *f, const uint8_t addr[16], uint64_t now) {
    int i;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++) {
        fips_session_t *s = &f->sess[i];
        if (memcmp(s->peer_addr, addr, 16) != 0) continue;
        if (s->state == S_LOOKUP) {
            if (start_setup(f, s, now)) memset(s, 0, sizeof *s);
        } else if (s->state == S_UP) {
            s->warm_left = WARM_PACKETS;
        }
    }
}

void fips_sess_lookup_failed(fips_t *f, const uint8_t addr[16]) {
    int i;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++)
        if (f->sess[i].state == S_LOOKUP && memcmp(f->sess[i].peer_addr, addr, 16) == 0) memset(&f->sess[i], 0, sizeof f->sess[i]);
}

int fips_session_ready(const fips_t *f, const uint8_t dest[32]) {
    uint8_t addr[16]; int i;
    fips_node_addr_of(dest, addr);
    for (i = 0; i < FIPS_MAX_SESSIONS; i++)
        if (f->sess[i].state == S_UP && memcmp(f->sess[i].peer_addr, addr, 16) == 0) return 1;
    return 0;
}

static int seal_frame(fips_t *f, fips_session_t *s, uint8_t flags, const uint8_t *coords, size_t clen,
                      uint8_t type, const uint8_t *body, size_t blen, uint64_t now) {
    uint8_t buf[FIPS_MTU]; size_t pl = 6 + blen, o;
    if (12 + clen + pl + 16 + 35 > 1400) return FIPS_ERR_TOOBIG;
    if (s->send_ctr == UINT64_MAX) return FIPS_ERR_STATE;
    buf[0] = 0x00; buf[1] = (uint8_t)(flags | (s->k ? 0x02 : 0)); put_le16(buf + 2, (uint16_t)pl); put_le64(buf + 4, s->send_ctr);
    o = 12;
    if (clen) { memcpy(buf + o, coords, clen); o += clen; }
    put_le32(f->pt, (uint32_t)(now - s->t_start_ms)); f->pt[4] = type; f->pt[5] = 0;
    if (blen) memcpy(f->pt + 6, body, blen);
    fips_aead_seal(s->send_key, s->send_ctr++, buf, 12, f->pt, pl, buf + o);
    s->t_used_ms = now;
    return fips_link_send_datagram(f, s->peer_addr, buf, o + pl + 16, now);
}

/* standalone CoordsWarmup: empty encrypted message whose cleartext coordinates warm the transit caches */
static void send_warmup(fips_t *f, fips_session_t *s, uint64_t now) {
    uint8_t coords[2 + 16 * FIPS_MAX_DEPTH + 2 + 16 * FIPS_MAX_DEPTH]; size_t cl;
    cl = put_coords_self(f, coords);
    cl += put_coords_dest(f, s, coords + cl);
    s->t_warm_ms = now;
    seal_frame(f, s, 0x01, coords, cl, 0x14, NULL, 0, now);
}

/* application message: piggyback coordinates (CP flag) on the first few packets of a session */
static int send_app(fips_t *f, fips_session_t *s, uint8_t type, const uint8_t *body, size_t blen, uint64_t now) {
    if (s->unanswered++ == 0) s->t_unanswered_ms = now;
    if (s->warm_left) {
        uint8_t coords[2 + 16 * FIPS_MAX_DEPTH + 2 + 16 * FIPS_MAX_DEPTH]; size_t cl;
        s->warm_left--;
        cl = put_coords_self(f, coords);
        cl += put_coords_dest(f, s, coords + cl);
        if (12 + cl + 6 + blen + 16 + 35 <= 1400) return seal_frame(f, s, 0x01, coords, cl, type, body, blen, now);
        send_warmup(f, s, now);                                  /* would not fit: warm the path with a separate message */
    }
    return seal_frame(f, s, 0, NULL, 0, type, body, blen, now);
}

static fips_session_t *find_up(fips_t *f, const uint8_t dest[32]) {
    uint8_t addr[16];
    fips_node_addr_of(dest, addr);
    return find_state(f, addr, S_UP);
}

int fips_send_data(fips_t *f, const uint8_t dest[32], uint16_t sp, uint16_t dp, const uint8_t *payload, size_t len, uint64_t now) {
    uint8_t body[FIPS_MTU]; fips_session_t *s;
    if (!f || !dest || (len && !payload)) return FIPS_ERR_ARG;
    if (len > 1100) return FIPS_ERR_TOOBIG;
    if (!(s = find_up(f, dest))) return FIPS_ERR_STATE;
    put_le16(body, sp); put_le16(body + 2, dp);
    if (len) memcpy(body + 4, payload, len);
    return send_app(f, s, 0x10, body, 4 + len, now);
}

int fips_send_packet(fips_t *f, const uint8_t dest[32], const uint8_t *pkt, size_t len, uint64_t now) {
    fips_session_t *s;
    if (!f || !dest || !pkt || !len) return FIPS_ERR_ARG;
    if (len > FIPS_MAX_PACKET) return FIPS_ERR_TOOBIG;
    if (!(s = find_up(f, dest))) return FIPS_ERR_STATE;
    return send_app(f, s, 0x15, pkt, len, now);
}

/* Skip two coordinate blocks starting at b[o]; returns new offset or 0 on error. */
static size_t skip_two_coords(const uint8_t *b, size_t n, size_t o) {
    size_t cnt;
    if (o + 2 > n) return 0;
    cnt = get_le16(b + o); if (cnt > 16) return 0; o += 2 + 16 * cnt; if (o + 2 > n) return 0;
    cnt = get_le16(b + o); if (cnt > 16) return 0; o += 2 + 16 * cnt;
    return o <= n ? o : 0;
}

/* ---- initiator: SessionAck -> msg3 -> established ---- */
static void on_ack(fips_t *f, fips_session_t *s, const uint8_t *b, size_t n, uint64_t now) {
    size_t o, cnt; fips_noise_t hs; uint8_t dh[32], epoch[8], k1[32], k2[32], m3[4 + 1 + 2 + XK_MSG3];
    const uint8_t *hp;
    if (s->state != S_AWAIT_ACK || n < 1 + 2) return;
    o = 1;
    cnt = get_le16(b + o); if (cnt > 16) return; o += 2 + 16 * cnt; if (o + 2 > n) return;
    cnt = get_le16(b + o); if (cnt > 16) return; o += 2 + 16 * cnt; if (o + 2 > n) return;
    if (get_le16(b + o) != XK_MSG2 || o + 2 + XK_MSG2 > n) return;
    hp = b + o + 2;
    hs = s->hs;
    fips_noise_mix_hash(&hs, hp, 33);                                       /* <- e  */
    if (fips_ecdh(s->e_secret, hp, dh)) return;                             /* ee */
    fips_noise_mix_key(&hs, dh);
    if (fips_noise_decrypt_hash(&hs, hp + 33, 24, epoch)) return;           /* epoch */
    /* msg3: -> s, se, epoch */
    m3[0] = 0x03; m3[1] = 0; put_le16(m3 + 2, 1 + 2 + XK_MSG3); m3[4] = 0; put_le16(m3 + 5, XK_MSG3);
    fips_noise_encrypt_hash(&hs, f->pub_comp, 33, m3 + 7);
    if (fips_ecdh(f->secret, hp, dh)) return;                               /* se: DH(s, re) */
    fips_noise_mix_key(&hs, dh);
    fips_noise_encrypt_hash(&hs, f->epoch, 8, m3 + 7 + 49);
    fips_noise_split(&hs, k1, k2);
    memcpy(s->send_key, k1, 32); memcpy(s->recv_key, k2, 32);
    memset(&s->hs, 0, sizeof s->hs); memset(s->e_secret, 0, 32);
    s->send_ctr = 0; memset(&s->replay, 0, sizeof s->replay);
    s->t_start_ms = s->t_used_ms = now; s->state = S_UP; s->k = 0; s->k_known = 1;
    fips_link_send_datagram(f, s->peer_addr, m3, sizeof m3, now);
    /* first sealed frame is a CoordsWarmup (empty body, CP flag): proves key possession to the responder */
    s->warm_left = WARM_PACKETS;
    send_warmup(f, s, now);
}

/* ---- responder: SessionSetup -> SessionAck ... msg3 -> established ---- */
static void on_setup(fips_t *f, const uint8_t src[16], const uint8_t *b, size_t n, uint64_t now) {
    fips_session_t *s; size_t o, o_dest, cnt, ack_len; uint8_t dh[32], e_pub[33], k_epoch[8];
    const uint8_t *e_i; uint8_t *a;
    f->diag[FIPS_DG_SETUP_RX]++;
    fips_trace(f, FIPS_TR_FSP_SETUP_RX, src[0], now);
    if (!f->io.accept_peer || n < 1 + 2 + 2 + 2) { f->diag[FIPS_DG_SETUP_REJ]++; return; }
    if ((s = find_state(f, src, S_AWAIT_MSG3))) {              /* initiator resent: repeat our ack */
        fips_link_send_datagram(f, src, s->setup_pkt, s->setup_len, now);
        return;
    }
    if ((s = find_state(f, src, S_AWAIT_ACK))) {                 /* simultaneous initiation: smaller NodeAddr wins as initiator */
        if (memcmp(f->node_addr, src, 16) < 0) return;
        memset(s, 0, sizeof *s);
    }
    /* parse: flags, src coords, dest coords, hs_len, msg1 */
    o = 1;
    cnt = get_le16(b + o); if (cnt > 16) return; o_dest = o + 2 + 16 * cnt; /* start of dest coords */
    if (!(o = skip_two_coords(b, n, o))) return;
    if (o + 2 > n || get_le16(b + o) != XK_MSG1 || o + 2 + XK_MSG1 > n) return;
    e_i = b + o + 2;
    fips_coords_put(f, src, b + 3, get_le16(b + 1), 0, now);                   /* initiator's coordinates: needed for the ack and warmups */
    s = alloc_slot(f);
    memset(s, 0, sizeof *s);
    memcpy(s->peer_addr, src, 16); s->responder = 1;
    fips_noise_init(&s->hs, FIPS_PROTO_XK, f->pub_xonly);
    fips_noise_mix_hash(&s->hs, e_i, 33);                                    /* <- e  */
    if (fips_ecdh(f->secret, e_i, dh)) { s->state = S_FREE; return; }        /* es */
    fips_noise_mix_key(&s->hs, dh);
    if (fips_gen_keypair(&f->io, s->e_secret, e_pub)) { s->state = S_FREE; return; }
    fips_noise_mix_hash(&s->hs, e_pub, 33);                                  /* -> e  */
    if (fips_ecdh(s->e_secret, e_i, dh)) { s->state = S_FREE; return; }      /* ee */
    fips_noise_mix_key(&s->hs, dh);
    memcpy(k_epoch, f->epoch, 8);

    a = s->setup_pkt;
    a[0] = 0x02; a[1] = 0;
    o = 4; a[o++] = 0;                                                       /* flags */
    o += put_coords_self(f, a + o);
    {   /* dest coords = the initiator's own (src) coordinates, copied */
        size_t scnt = get_le16(b + 1), slen = 2 + 16 * scnt;
        memcpy(a + o, b + 1, slen); o += slen; (void)o_dest;
    }
    put_le16(a + o, XK_MSG2); o += 2;
    memcpy(a + o, e_pub, 33);
    fips_noise_encrypt_hash(&s->hs, k_epoch, 8, a + o + 33);                 /* epoch */
    o += XK_MSG2;
    ack_len = o; put_le16(a + 2, (uint16_t)(ack_len - 4));
    s->setup_len = ack_len;
    s->state = S_AWAIT_MSG3; s->t_setup_ms = s->t_used_ms = now;
    fips_link_send_datagram(f, src, a, ack_len, now);
}

static void on_msg3(fips_t *f, const uint8_t src[16], const uint8_t *b, size_t n, uint64_t now) {
    fips_session_t *s = find_state(f, src, S_AWAIT_MSG3), *old; fips_noise_t hs;
    uint8_t s33[33], epoch[8], dh[32], k1[32], k2[32], addr[16]; int i;
    if (!s || n < 1 + 2 + XK_MSG3 || get_le16(b + 1) != XK_MSG3) return;
    hs = s->hs;
    if (fips_noise_decrypt_hash(&hs, b + 3, 49, s33)) return;                /* s  */
    if (s33[0] != 0x02 && s33[0] != 0x03) return;
    if (fips_ecdh(s->e_secret, s33, dh)) return;                             /* se: DH(e, rs) */
    fips_noise_mix_key(&hs, dh);
    if (fips_noise_decrypt_hash(&hs, b + 3 + 49, 24, epoch)) return;
    fips_node_addr_of(s33 + 1, addr);
    if (memcmp(addr, src, 16) != 0) return;                                  /* claimed identity must match the datagram source */
    if (!f->io.accept_peer(f->io.ud, s33 + 1)) { memset(s, 0, sizeof *s); return; }
    fips_noise_split(&hs, k1, k2);
    for (i = 0; i < FIPS_MAX_SESSIONS; i++) {                               /* rekey of a live session: new keys wait as the pending epoch */
        old = &f->sess[i];
        if (old != s && old->state == S_UP && memcmp(old->peer_addr, src, 16) == 0) {
            memcpy(old->pend_recv, k1, 32); memcpy(old->pend_send, k2, 32);
            memset(&old->pend_replay, 0, sizeof old->pend_replay); old->pend = 1;
            fips_trace(f, FIPS_TR_FSP_MSG3_REKEY, src[0], now);
            memset(s, 0, sizeof *s);
            return;
        }
    }
    memcpy(s->recv_key, k1, 32); memcpy(s->send_key, k2, 32);                /* responder: recv = k1, send = k2 */
    memcpy(s->peer_xonly, s33 + 1, 32);
    memset(&s->hs, 0, sizeof s->hs); memset(s->e_secret, 0, 32);
    s->send_ctr = 0; memset(&s->replay, 0, sizeof s->replay);
    s->t_start_ms = s->t_used_ms = now;
    s->k = 0; s->k_known = 0;                                                /* learned from the peer's first authenticated frame */
    s->state = S_UP;
    s->warm_left = WARM_PACKETS;
    fips_trace(f, FIPS_TR_FSP_MSG3_NEW, src[0], now);
    send_warmup(f, s, now);                                                  /* warm the return path as soon as keys exist */
}

static void on_established(fips_t *f, fips_session_t *s, const uint8_t *d, size_t n, uint64_t now) {
    uint8_t flags = d[1]; uint64_t ctr = get_le64(d + 4); size_t off = 12, pl; uint8_t K = (flags & 0x02) ? 1 : 0; int which = 0;
    if (flags & 0x04) return;                                   /* U: plaintext error signal (CoordsRequired/PathBroken/MtuExceeded) */
    if (s->state != S_UP) return;
    f->diag[FIPS_DG_EST_RX]++;
    if (flags & 0x01) {                                         /* CP: skip cleartext coordinates */
        if (!(off = skip_two_coords(d, n, off))) return;
    }
    if (off + 16 > n) return;
    pl = n - off - 16;
    if (pl > sizeof f->pt || pl < 6 || get_le16(d + 2) != pl) { f->diag[FIPS_DG_EST_BAD]++; return; }
    /* try the key set the K flag points at, then the other candidates (a peer restart or a lost flip must not strand us) */
    if ((!s->k_known || K == s->k) && fips_replay_check(&s->replay, ctr) && !fips_aead_open(s->recv_key, ctr, d, 12, d + off, n - off, f->pt)) which = 1;
    else if (s->prev && K == s->prev_k && fips_replay_check(&s->prev_replay, ctr) && !fips_aead_open(s->prev_recv, ctr, d, 12, d + off, n - off, f->pt)) which = 2;
    else if (s->pend && fips_replay_check(&s->pend_replay, ctr) && !fips_aead_open(s->pend_recv, ctr, d, 12, d + off, n - off, f->pt)) which = 3;
    if (!which) { f->diag[FIPS_DG_EST_AEAD]++; return; }
    if (which == 1) { fips_replay_accept(&s->replay, ctr); if (!s->k_known) { s->k = K; s->k_known = 1; send_warmup(f, s, now); } }
    else if (which == 2) fips_replay_accept(&s->prev_replay, ctr);
    else {                                                      /* the peer cut over to the new epoch: promote it, keep the old receive key for the drain */
        fips_replay_accept(&s->pend_replay, ctr);
        memcpy(s->prev_recv, s->recv_key, 32); s->prev_replay = s->replay; s->prev_k = s->k; s->prev = 1; s->t_prev_ms = now;
        memcpy(s->recv_key, s->pend_recv, 32); memcpy(s->send_key, s->pend_send, 32); s->replay = s->pend_replay;
        s->send_ctr = 0; s->pend = 0; s->k = K; s->k_known = 1; s->unanswered = 0;
        f->diag[FIPS_DG_PROMOTE]++; fips_trace(f, FIPS_TR_FSP_PROMOTE, s->peer_addr[0], now);
        send_warmup(f, s, now);                                 /* authenticated reply on the new epoch confirms the cutover for the peer */
    }
    f->diag[FIPS_DG_EST_OK]++; f->diag[FIPS_DG_LAST_PT4] = f->pt[4];
    s->t_used_ms = now; s->unanswered = 0;
    if (f->pt[4] != 0x12) {                                     /* count what the peer sent us; a report is owed for it */
        s->rx_pkts++; s->rx_bytes += pl; if (ctr > s->rx_hi) s->rx_hi = ctr;
        s->rx_echo_ts = get_le32(f->pt); if (!s->rx_echo_ts) s->rx_echo_ts = 1;
        s->t_rx_ms = now; s->rr_pending = 1;
    }
    if (f->pt[4] == 0x10 && pl >= 6 + 4 && f->io.on_data)
        f->io.on_data(f->io.ud, s->peer_addr, get_le16(f->pt + 6), get_le16(f->pt + 8), f->pt + 10, pl - 10);
    else if (f->pt[4] == 0x15 && f->io.on_packet) {
        f->diag[FIPS_DG_PKT_DELIVERED]++;
        f->io.on_packet(f->io.ud, s->peer_xonly, f->pt + 6, pl - 6);
    }
}

/* plaintext error signals from a transit node: CoordsRequired (0x20), PathBroken (0x21), MtuExceeded (0x22) */
static void on_error_signal(fips_t *f, const uint8_t *b, size_t n, uint64_t now) {
    fips_session_t *s;
    f->diag[FIPS_DG_ERRSIG]++; if (n >= 1) f->diag[FIPS_DG_LAST_ERR] = b[0];
    if (n < 34 || (b[0] != 0x20 && b[0] != 0x21)) return;
    if (!(s = find_state(f, b + 2, S_UP))) return;
    if (s->t_warm_ms == 0 || now - s->t_warm_ms >= COORDS_RESP_INTERVAL_MS) {
        send_warmup(f, s, now);
        s->warm_left = WARM_PACKETS;
        fips_lookup_start(f, s->peer_xonly, now);                 /* refresh the destination's coordinates */
    }
}

void fips_sess_input(fips_t *f, const uint8_t src[16], const uint8_t *p, size_t n, uint64_t now) {
    fips_session_t *s;
    if (n < 4 || (p[0] >> 4) != 0 || get_le16(p + 2) > n - 4) return;
    switch (p[0] & 15) {
    case 1: if (get_le16(p + 2) == n - 4) on_setup(f, src, p + 4, n - 4, now); break;
    case 2: f->diag[FIPS_DG_ACK_RX]++; if ((s = find_state(f, src, S_AWAIT_ACK)) && get_le16(p + 2) == n - 4) on_ack(f, s, p + 4, n - 4, now); break;
    case 3: f->diag[FIPS_DG_MSG3_RX]++; if (get_le16(p + 2) == n - 4) on_msg3(f, src, p + 4, n - 4, now); break;
    case 0:
        if (p[1] & 0x04) { on_error_signal(f, p + 4, n - 4, now); break; }
        if (n >= 28 && (s = find_state(f, src, S_UP))) on_established(f, s, p, n, now);
        else f->diag[FIPS_DG_EST_NOSESS]++;
        break;
    default: break;
    }
}

/* MMP ReceiverReport body (66 bytes after the 6-byte inner header): only the counters, echo and dwell are filled in */
void fips_build_receiver_report(const fips_session_t *s, uint64_t now, uint8_t b[66]) {
    uint64_t dwell = now - s->t_rx_ms;
    memset(b, 0, 66);
    put_le64(b + 2, s->rx_hi); put_le64(b + 10, s->rx_pkts); put_le64(b + 18, s->rx_bytes);
    put_le32(b + 26, s->rx_echo_ts); put_le16(b + 30, (uint16_t)(dwell > 0xffff ? 0xffff : dwell));
    put_le32(b + 58, (uint32_t)(s->rx_pkts - s->rr_last_pkts)); put_le32(b + 62, (uint32_t)(s->rx_bytes - s->rr_last_bytes));
}

static void send_receiver_report(fips_t *f, fips_session_t *s, uint64_t now) {
    uint8_t b[66];
    fips_build_receiver_report(s, now, b);
    s->rr_last_pkts = s->rx_pkts; s->rr_last_bytes = s->rx_bytes; s->t_rr_ms = now; s->rr_pending = 0;
    if (seal_frame(f, s, 0, NULL, 0, 0x12, b, sizeof b, now) == FIPS_OK) f->diag[FIPS_DG_RR_TX]++;
}

void fips_sess_tick(fips_t *f, uint64_t now) {
    int i;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++) {
        fips_session_t *s = &f->sess[i];
        if (s->state == S_UP && s->rr_pending && now - s->t_rr_ms >= RR_MIN_MS) send_receiver_report(f, s, now);
        if (s->state == S_UP && s->prev && now - s->t_prev_ms >= FSP_DRAIN_MS) { s->prev = 0; memset(s->prev_recv, 0, 32); }
        if (s->state == S_AWAIT_MSG3 && now - s->t_setup_ms >= MSG3_WAIT_MS) { memset(s, 0, sizeof *s); continue; }
        if (s->state == S_UP && s->unanswered >= DEAD_PEER_MIN_PKTS && now - s->t_unanswered_ms >= DEAD_PEER_MS) {
            f->diag[FIPS_DG_DEAD_RESET]++; fips_trace(f, FIPS_TR_FSP_DEAD_RESET, s->peer_addr[0], now);
            memset(s, 0, sizeof *s);                                 /* the next packet opens a fresh session */
            continue;
        }
        if (s->state == S_LOOKUP && now - s->t_setup_ms >= LOOKUP_WAIT_MS) { memset(s, 0, sizeof *s); continue; }
        if (s->state != S_AWAIT_ACK) continue;
        if (now - s->t_setup_ms >= (1000ULL << s->resends)) {
            if (++s->resends > 4) { memset(s, 0, sizeof *s); continue; }
            s->t_setup_ms = now;
            fips_link_send_datagram(f, s->peer_addr, s->setup_pkt, s->setup_len, now);
        }
    }
}

void fips_sess_reset_link(fips_t *f) {
    int i;
    for (i = 0; i < FIPS_MAX_SESSIONS; i++) if (f->sess[i].state == S_AWAIT_ACK || f->sess[i].state == S_AWAIT_MSG3 || f->sess[i].state == S_LOOKUP) memset(&f->sess[i], 0, sizeof f->sess[i]);
}
