/* Mesh participation for a leaf that hangs off one upstream FIPS node (e.g. a public seed).
 *
 * Without this the upstream can only deliver to us if it is also the other end of the session. With it we can
 * talk to any node in the mesh through the upstream, including nodes behind NAT that are only reachable via
 * that same upstream:
 *   - TreeAnnounce: we declare the upstream as our parent, so our coordinates are [us] + upstream's ancestry.
 *   - FilterAnnounce: a bloom filter holding just our address, so other nodes' lookups for us reach us.
 *   - LookupRequest: we ask the mesh for a destination's coordinates (verified with the target's signature).
 *   - LookupResponse: we answer lookups that target us.
 *   - coordinate cache for building SessionSetup / CoordsWarmup.
 * We never forward anything and never become a parent.
 *
 * Role: we follow the FIPS "client-only" negotiation (fips-wire-formats.md, "Client role negotiation"):
 *   1. on link-up we send ClientSupport (0x53);
 *   2. once the upstream's tree bootstrap has arrived, we give it one announcement interval to answer with
 *      ClientSupport (or ClientOnly); if it does, we send ClientOnly (0x52 + declaration sequence) INSTEAD of
 *      TreeAnnounce and never declare a tree position;
 *   3. otherwise (upstream without leaf support) we do NOT advertise ourselves as a router, because we cannot forward
 *      transit traffic: we enter role 3 ("waiting"), report it (FIPS_TR_ROLE_UNSUPPORTED, role=3) and retry ClientSupport
 *      every 30 s. Only fips_t.allow_router_fallback=1 (tests/legacy interop) restores the old TreeAnnounce fallback.
 * If the upstream answers later we switch to ClientOnly with an advanced sequence.
 */
#include "fips_internal.h"

#define COORD_TTL_MS 300000ULL
#define LOOKUP_ATTEMPTS 4
static const uint32_t lookup_timeout_ms[LOOKUP_ATTEMPTS] = {1000, 2000, 4000, 8000};

/* ------------------------------------------------------------ coordinate cache --- */

const fips_coord_t *fips_coords_get(const fips_t *f, const uint8_t addr[16]) {
    int i;
    for (i = 0; i < FIPS_COORD_CACHE; i++)
        if (f->cc[i].used && memcmp(f->cc[i].addr, addr, 16) == 0) return &f->cc[i];
    return NULL;
}

void fips_coords_put(fips_t *f, const uint8_t addr[16], const uint8_t *raw, size_t n, int verified, uint64_t now) {
    fips_coord_t *e = NULL; int i; size_t k;
    if (n == 0 || n > FIPS_MAX_DEPTH) return;
    for (i = 0; i < FIPS_COORD_CACHE; i++)
        if (f->cc[i].used && memcmp(f->cc[i].addr, addr, 16) == 0) { e = &f->cc[i]; break; }
    if (e && e->verified && !verified && now - e->t_ms < COORD_TTL_MS) return;  /* a hint never replaces a verified entry */
    if (!e) {
        for (i = 0; i < FIPS_COORD_CACHE && !e; i++) if (!f->cc[i].used) e = &f->cc[i];
        for (i = 0; i < FIPS_COORD_CACHE && !e; i++) e = &f->cc[i];           /* full: replace the oldest */
        for (i = 0; i < FIPS_COORD_CACHE; i++) if (f->cc[i].t_ms < e->t_ms) e = &f->cc[i];
    }
    memset(e, 0, sizeof *e);
    e->used = 1; e->verified = verified ? 1 : 0; e->n = (uint8_t)n; e->t_ms = now;
    memcpy(e->addr, addr, 16);
    for (k = 0; k < n; k++) memcpy(e->c[k], raw + 16 * k, 16);
}

size_t fips_put_coords_self(const fips_t *f, uint8_t *o) {
    size_t n = 1 + f->up_anc_n, i;
    put_le16(o, (uint16_t)n);
    memcpy(o + 2, f->node_addr, 16);
    for (i = 0; i < f->up_anc_n; i++) memcpy(o + 2 + 16 * (1 + i), f->up_anc[i], 16);
    return 2 + 16 * n;
}

size_t fips_put_coords_of(const fips_t *f, const uint8_t addr[16], uint8_t *o) {
    size_t i; const fips_coord_t *e;
    if (memcmp(addr, f->upstream_addr, 16) == 0 && f->up_anc_n) {
        put_le16(o, f->up_anc_n);
        for (i = 0; i < f->up_anc_n; i++) memcpy(o + 2 + 16 * i, f->up_anc[i], 16);
        return 2 + 16 * (size_t)f->up_anc_n;
    }
    if ((e = fips_coords_get(f, addr))) {
        put_le16(o, e->n);
        for (i = 0; i < e->n; i++) memcpy(o + 2 + 16 * i, e->c[i], 16);
        return 2 + 16 * (size_t)e->n;
    }
    return 0;
}

/* ------------------------------------------------------------------ helpers --- */

static void sha256(const uint8_t *d, size_t n, uint8_t out[32]) {
    nvpn_sha256_ctx c;
    nvpn_sha256_init(&c); nvpn_sha256_update(&c, d, n); nvpn_sha256_final(&c, out);
}

/* the proof / declaration signatures are Schnorr over SHA-256 of the message bytes */
static int sign_msg(fips_t *f, const uint8_t *msg, size_t n, uint8_t sig[64]) {
    uint8_t dg[32], aux[32];
    sha256(msg, n, dg);
    f->io.random(f->io.ud, aux, 32);
    return nvpn_schnorr_sign(f->secret, dg, aux, sig);
}

static int verify_msg(const uint8_t pk[32], const uint8_t *msg, size_t n, const uint8_t sig[64]) {
    uint8_t dg[32];
    sha256(msg, n, dg);
    return nvpn_schnorr_verify(pk, dg, sig);
}

static uint64_t now_unix(const fips_t *f, uint64_t now) { return f->up_ts + (now - f->t_up_ts_ms) / 1000; }
uint64_t fips_unix_now(fips_t *f, uint64_t now) {
    uint64_t u;
    if (!f->up_ts) return 0;
    u = now_unix(f, now);
    if (u < f->unix_hi) u = f->unix_hi;
    return f->unix_hi = u;
}

/* ------------------------------------------------------- tree + filter announce --- */

static void send_tree_announce(fips_t *f, uint64_t now) {
    uint8_t b[35 + 32 * FIPS_MAX_DEPTH + 64], sd[48]; size_t o, i; uint64_t ts = now_unix(f, now);
    if (!f->up_anc_n) return;
    b[0] = 1;
    put_le64(b + 1, f->tree_seq); put_le64(b + 9, ts);
    memcpy(b + 17, f->upstream_addr, 16);                          /* parent = the upstream */
    put_le16(b + 33, (uint16_t)(1 + f->up_anc_n));
    o = 35;
    memcpy(b + o, f->node_addr, 16); put_le64(b + o + 16, f->tree_seq); put_le64(b + o + 24, ts); o += 32;
    for (i = 0; i < f->up_anc_n; i++) { memcpy(b + o, f->up_anc_raw[i], 32); o += 32; }
    memcpy(sd, f->node_addr, 16); memcpy(sd + 16, f->upstream_addr, 16);
    put_le64(sd + 32, f->tree_seq); put_le64(sd + 40, ts);
    if (sign_msg(f, sd, sizeof sd, b + o) != NVPN_OK) return;
    fips_link_send_msg(f, FIPS_MSG_TREE_ANNOUNCE, b, o + 64, now);
}

static void send_filter_announce(fips_t *f, uint64_t now) {
    uint8_t b[10 + 1024], dg[32]; uint64_t h1, h2, k; int i;
    memset(b, 0, sizeof b);
    put_le64(b, ++f->filter_seq);
    b[8] = 5; b[9] = 1;                                            /* 5 hashes, size class 1 = 1024 bytes */
    sha256(f->node_addr, 16, dg);
    h1 = get_le64(dg); h2 = get_le64(dg + 8);
    for (i = 0; i < 5; i++) {
        k = (h1 + (uint64_t)i * h2) % 8192ULL;
        b[10 + k / 8] |= (uint8_t)(1u << (k % 8));
    }
    fips_link_send_msg(f, FIPS_MSG_FILTER_ANNOUNCE, b, sizeof b, now);
}

static void send_client_support(fips_t *f, uint64_t now) {
    if (fips_link_send_msg(f, FIPS_MSG_CLIENT_SUPPORT, NULL, 0, now) == FIPS_OK) fips_trace(f, FIPS_TR_ROLE_SUPPORT_TX, f->role, now);
}

static void send_client_only(fips_t *f, uint64_t now) {
    uint8_t b[8];
    put_le64(b, f->client_seq);
    if (fips_link_send_msg(f, FIPS_MSG_CLIENT_ONLY, b, sizeof b, now) == FIPS_OK) fips_trace(f, FIPS_TR_ROLE_CLIENT_TX, (uint8_t)f->client_seq, now);
}

void fips_mesh_link_up(fips_t *f, uint64_t now) {
    f->up_anc_n = 0;                                               /* the upstream re-sends its TreeAnnounce on a new link */
    f->announce_due = 0; f->announce_n = 0;
    f->role = 0; f->peer_client_support = 0; f->support_sent = 0; f->t_role_start_ms = now;
    if (f->client_role_off == 1) { f->role = 2; return; }   /* 2 = test hook: send ClientSupport but ignore any answer (legacy upstream) */
    send_client_support(f, now);                                   /* negotiation starts before our first announcement */
}

void fips_mesh_on_role_msg(fips_t *f, uint8_t type, const uint8_t *b, size_t n, uint64_t now) {
    (void)b;
    if (type == FIPS_MSG_CLIENT_SUPPORT && n != 0) return;
    if (type == FIPS_MSG_CLIENT_ONLY && n != 8) return;
    fips_trace(f, FIPS_TR_ROLE_SUPPORT_RX, type, now);
    if (f->client_role_off) return;
    if (!f->peer_client_support) {
        f->peer_client_support = 1;
        if (f->role == 2 || f->role == 3) {                        /* we had fallen back / were waiting: switch to the client role */
            f->role = 0; f->announce_n = 0; f->announce_due = 1; f->t_announce_ms = now; f->support_sent = 2;
        }
        if (f->up_anc_n) { f->announce_due = 1; if (f->t_announce_ms > now) f->t_announce_ms = now; }
    }
}

void fips_mesh_on_tree_announce(fips_t *f, const uint8_t *b, size_t n, uint64_t now) {
    /* body (after msg_type): version(1) seq(8) ts(8) parent(16) count(2) entries(32*cnt) sig(64) */
    uint16_t cnt; uint8_t sd[48]; size_t i; int changed = 0;
    if (n < 35 || b[0] != 1) return;
    cnt = get_le16(b + 33);
    if (cnt == 0 || cnt > FIPS_MAX_DEPTH - 1 || n < 35 + (size_t)cnt * 32 + 64) return;
    if (memcmp(b + 35, f->upstream_addr, 16) != 0) return;         /* the first entry is the announcing node itself */
    memcpy(sd, f->upstream_addr, 16); memcpy(sd + 16, b + 17, 16); memcpy(sd + 32, b + 1, 8); memcpy(sd + 40, b + 9, 8);
    if (verify_msg(f->upstream_xonly, sd, sizeof sd, b + 35 + (size_t)cnt * 32) != NVPN_OK) return;
    if (cnt != f->up_anc_n) changed = 1;
    for (i = 0; i < cnt && !changed; i++) if (memcmp(f->up_anc[i], b + 35 + i * 32, 16) != 0) changed = 1;
    for (i = 0; i < cnt; i++) { memcpy(f->up_anc[i], b + 35 + i * 32, 16); memcpy(f->up_anc_raw[i], b + 35 + i * 32, 32); }
    f->up_anc_n = (uint8_t)cnt;
    f->up_ts = get_le64(b + 9); f->t_up_ts_ms = now;
    if (f->tree_seq == 0) {                                        /* unix seconds keep the sequence monotonic across restarts */
        f->tree_seq = f->up_ts > 1000000000ULL ? f->up_ts : 1;
    } else if (changed) {
        f->tree_seq++;
    }
    if (changed) { f->announce_n = 0; f->announce_due = 1; f->t_announce_ms = now; }
}

/* ------------------------------------------------------------------- lookups --- */

static int send_lookup(fips_t *f, fips_lookup_t *lk, uint64_t now) {
    uint8_t b[45 + 2 + 16 * FIPS_MAX_DEPTH]; size_t o;
    if (!f->up_anc_n) return 0;                                    /* we don't know our own coordinates yet */
    f->io.random(f->io.ud, lk->ids[lk->attempt], 8);
    memcpy(b, lk->ids[lk->attempt], 8);
    memcpy(b + 8, lk->target_addr, 16);
    memcpy(b + 24, f->node_addr, 16);
    b[40] = 64;                                                    /* ttl */
    put_le16(b + 41, 0);                                           /* min_mtu: no requirement */
    o = 43 + fips_put_coords_self(f, b + 43);
    lk->t_sent_ms = now;
    return fips_link_send_msg(f, FIPS_MSG_LOOKUP_REQUEST, b, o, now) == FIPS_OK;
}

int fips_lookup_start(fips_t *f, const uint8_t target_xonly[32], uint64_t now) {
    uint8_t addr[16]; int i; fips_lookup_t *lk = NULL;
    fips_node_addr_of(target_xonly, addr);
    for (i = 0; i < FIPS_MAX_LOOKUPS; i++) {
        if (f->lk[i].active && memcmp(f->lk[i].target_addr, addr, 16) == 0) return 0;   /* already running */
        if (!f->lk[i].active && !lk) lk = &f->lk[i];
    }
    if (!lk) return FIPS_ERR_NOSPACE;
    memset(lk, 0, sizeof *lk);
    lk->active = 1; lk->t_start_ms = now;
    memcpy(lk->target_xonly, target_xonly, 32); memcpy(lk->target_addr, addr, 16);
    if (!send_lookup(f, lk, now)) lk->t_sent_ms = 0;               /* sent from the tick once our coordinates are known */
    return 0;
}

void fips_mesh_on_lookup_response(fips_t *f, const uint8_t *b, size_t n, uint64_t now) {
    /* body: request_id(8) target(16) path_mtu(2) count(2) coords(16*cnt) proof(64) */
    uint16_t cnt; int i, a; fips_lookup_t *lk = NULL; uint8_t msg[8 + 16 + 2 + 16 * FIPS_MAX_DEPTH];
    if (n < 28) return;
    cnt = get_le16(b + 26);
    if (cnt == 0 || cnt > FIPS_MAX_DEPTH || n < 28 + (size_t)cnt * 16 + 64) return;
    for (i = 0; i < FIPS_MAX_LOOKUPS && !lk; i++) {
        if (!f->lk[i].active || memcmp(f->lk[i].target_addr, b + 8, 16) != 0) continue;
        for (a = 0; a <= f->lk[i].attempt && a < LOOKUP_ATTEMPTS; a++)
            if (memcmp(f->lk[i].ids[a], b, 8) == 0) { lk = &f->lk[i]; break; }
    }
    if (!lk) return;                                               /* unsolicited or stale */
    memcpy(msg, b, 24); memcpy(msg + 24, b + 26, 2 + (size_t)cnt * 16);
    if (verify_msg(lk->target_xonly, msg, 24 + 2 + (size_t)cnt * 16, b + 28 + (size_t)cnt * 16) != NVPN_OK) return;
    fips_coords_put(f, lk->target_addr, b + 28, cnt, 1, now);
    lk->active = 0;
    fips_sess_coords_ready(f, b + 8, now);
}

void fips_mesh_on_lookup_request(fips_t *f, const uint8_t *b, size_t n, uint64_t now) {
    /* body: request_id(8) target(16) origin(16) ttl(1) min_mtu(2) count(2) coords(16*cnt) */
    uint16_t cnt; uint8_t r[28 + 2 + 16 * FIPS_MAX_DEPTH + 64], msg[8 + 16 + 2 + 16 * FIPS_MAX_DEPTH]; size_t o;
    if (n < 45) return;
    cnt = get_le16(b + 43);
    if (cnt == 0 || cnt > FIPS_MAX_DEPTH || n < 45 + (size_t)cnt * 16) return;
    if (memcmp(b + 8, f->node_addr, 16) != 0 || !f->up_anc_n) return;   /* a leaf only answers for itself */
    fips_coords_put(f, b + 24, b + 45, cnt, 0, now);               /* the origin's coordinates are a useful hint for the reply */
    memcpy(r, b, 8); memcpy(r + 8, f->node_addr, 16); put_le16(r + 24, 0xffff);
    o = 26 + fips_put_coords_self(f, r + 26);
    memcpy(msg, r, 24); memcpy(msg + 24, r + 26, o - 26);
    if (sign_msg(f, msg, 24 + (o - 26), r + o) != NVPN_OK) return;
    fips_link_send_msg(f, FIPS_MSG_LOOKUP_RESPONSE, r, o + 64, now);
}

/* ---------------------------------------------------------------------- tick --- */

void fips_mesh_tick(fips_t *f, uint64_t now) {
    int i;
    for (i = 0; i < FIPS_COORD_CACHE; i++)
        if (f->cc[i].used && now - f->cc[i].t_ms > COORD_TTL_MS) f->cc[i].used = 0;

    if (f->announce_due && now >= f->t_announce_ms) {
        static const uint32_t gap_ms[] = {2000, 4000, 8000};
        int wait = 0;
        if (f->role == 3 && !f->peer_client_support) {             /* waiting for a leaf-capable neighbour: just retry */
            send_client_support(f, now);
            f->t_announce_ms = now + 30000;
            wait = 1;
        } else if (f->role == 0 || f->role == 3) {
            if (f->peer_client_support) {                          /* the upstream understands the client role */
                f->role = 1;
                if (f->tree_seq == 0) f->tree_seq = 1;
                f->client_seq = ++f->tree_seq;                     /* advances past any router declaration we sent */
            } else if (f->support_sent == 0) {                     /* first interval: let a capable upstream answer */
                f->support_sent = 1;
                send_client_support(f, now);
                f->t_announce_ms = now + gap_ms[0];
                wait = 1;
            } else if (f->allow_router_fallback) {                 /* opt-in (tests/legacy): advertise as a router anyway */
                f->role = 2;
                fips_trace(f, FIPS_TR_ROLE_FALLBACK, 0, now);
            } else {                                               /* upstream lacks leaf support: stay silent, keep retrying */
                f->role = 3;
                fips_trace(f, FIPS_TR_ROLE_UNSUPPORTED, 0, now);
                send_client_support(f, now);
                f->t_announce_ms = now + 30000;
                wait = 1;
            }
        }
        if (!wait) {
            if (f->role == 1) send_client_only(f, now);
            else { send_tree_announce(f, now); fips_trace(f, FIPS_TR_ROLE_TREE_TX, 0, now); }
            send_filter_announce(f, now);
            f->t_announce_ms = now + (f->announce_n < 3 ? gap_ms[f->announce_n] : 60000);
            if (f->announce_n < 255) f->announce_n++;
        }
    }

    for (i = 0; i < FIPS_MAX_LOOKUPS; i++) {
        fips_lookup_t *lk = &f->lk[i];
        if (!lk->active) continue;
        if (lk->t_sent_ms == 0) { if (!send_lookup(f, lk, now)) { if (now - lk->t_start_ms > 15000) goto fail; lk->t_sent_ms = 0; } continue; }
        if (now - lk->t_sent_ms < lookup_timeout_ms[lk->attempt]) continue;
        if (++lk->attempt >= LOOKUP_ATTEMPTS) goto fail;
        send_lookup(f, lk, now);
        continue;
    fail:
        lk->active = 0;
        fips_sess_lookup_failed(f, lk->target_addr);
    }
}
