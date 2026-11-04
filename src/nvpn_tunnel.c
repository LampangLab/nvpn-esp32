#include "nvpn_tunnel.h"
#include <string.h>
#include <stdio.h>

#define PENDING_MAX_AGE_MS 15000   /* a multi-hop session needs a lookup first */

static int on_accept(void *ud, const uint8_t peer[32]) {
    nvpn_tunnel_t *t = (nvpn_tunnel_t *)ud;
    return nvpn_roster_is_member(t->roster, peer) && memcmp(peer, t->self_pk, 32) != 0;
}

/* nostr-vpn application control frames ride in the same FIPS message type as IPv4 packets:
 *   "NVPN-FIPS-CTRL\0" + {"v":1,"frame":{"kind":"ping","network_id":"..","sent_at":N}}
 * The desktop app pings every member about every 10 s and treats the Pong as proof of life (presence). We answer Ping only;
 * stateful frames (JoinRoster etc.) are FIPS-TCP on port 7370 and are not handled here. */
#define CTRL_MAGIC "NVPN-FIPS-CTRL"
static const char *json_find(const char *s, size_t n, const char *key) {   /* pointer to the text after `"key":` */
    size_t kl = strlen(key), i;
    for (i = 0; i + kl + 3 <= n; i++)
        if (s[i] == '"' && memcmp(s + i + 1, key, kl) == 0 && s[i + 1 + kl] == '"' && s[i + 2 + kl] == ':') return s + i + 3 + kl;
    return NULL;
}

static int handle_ctrl(nvpn_tunnel_t *t, const uint8_t peer[32], const uint8_t *pkt, size_t len) {
    const char *j; size_t n, i; char nid[65]; uint64_t sent_at = 0, unow; char out[200]; int o;
    if (len < 16 || memcmp(pkt, CTRL_MAGIC, 14) != 0 || pkt[14] != 0) return 0;
    j = (const char *)pkt + 15; n = len - 15;
    if (!nvpn_roster_is_member(t->roster, peer) || memcmp(peer, t->self_pk, 32) == 0) return 1;
    {   const char *k = json_find(j, n, "kind");
        if (!k || (size_t)(j + n - k) < 6 || memcmp(k, "\"ping\"", 6) != 0) { t->stats.ctrl_other_rx++; return 1; } }
    {   const char *v = json_find(j, n, "network_id"); size_t m = 0;
        if (!v || v >= j + n || *v != '"') return 1;
        for (v++; v < j + n && *v != '"' && m < 64; v++) {
            if (!((*v >= '0' && *v <= '9') || (*v >= 'a' && *v <= 'z') || (*v >= 'A' && *v <= 'Z') || *v == '-' || *v == '_' || *v == '.')) return 1;
            nid[m++] = *v;
        }
        if (v >= j + n || *v != '"') return 1;
        nid[m] = 0; }
    {   const char *v = json_find(j, n, "sent_at");
        if (!v) return 1;
        for (i = 0; v + i < j + n && v[i] >= '0' && v[i] <= '9' && i < 19; i++) sent_at = sent_at * 10 + (uint64_t)(v[i] - '0');
        if (i == 0) return 1; }
    t->stats.ctrl_ping_rx++;
    unow = fips_unix_now(&t->fips, t->now_ms);
    if (!unow) unow = sent_at;                                     /* no clock yet: echo the sender's time */
    memcpy(out, CTRL_MAGIC "\0", 15);
    o = 15 + snprintf(out + 15, sizeof out - 15, "{\"v\":1,\"frame\":{\"kind\":\"pong\",\"network_id\":\"%s\",\"sent_at\":%llu,\"replied_at\":%llu}}",
                      nid, (unsigned long long)sent_at, (unsigned long long)unow);
    if (o > 15 && (size_t)o < sizeof out && fips_send_packet(&t->fips, peer, (const uint8_t *)out, (size_t)o, t->now_ms) == FIPS_OK) t->stats.ctrl_pong_tx++;
    return 1;
}

static void on_packet(void *ud, const uint8_t peer[32], const uint8_t *pkt, size_t len) {
    nvpn_tunnel_t *t = (nvpn_tunnel_t *)ud;
    if (handle_ctrl(t, peer, pkt, len)) return;
    if (!nvpn_admit_inbound(t->roster, peer, t->self_ip, pkt, len)) {
        t->stats.rx_rejected++;
        if (len && (pkt[0] >> 4) != 4) t->stats.rej_not_ipv4++;
        memset(t->stats.last_rej_head, 0, sizeof t->stats.last_rej_head);
        memcpy(t->stats.last_rej_head, pkt, len < sizeof t->stats.last_rej_head ? len : sizeof t->stats.last_rej_head);
        if (len >= 20) {
            memcpy(t->stats.last_rej_src, pkt + 12, 4); memcpy(t->stats.last_rej_dst, pkt + 16, 4);
            t->stats.last_rej_proto = pkt[9]; t->stats.last_rej_len = (uint16_t)len;
        }
        return;
    }
    t->stats.rx_pkts++;
    if (t->io.deliver) t->io.deliver(t->io.ud, pkt, len);
}

static void fips_tx(void *ud, const uint8_t *p, size_t n) { nvpn_tunnel_t *t = (nvpn_tunnel_t *)ud; t->stats.udp_tx++; t->io.send(t->io.ud, p, n); }
static void fips_rnd(void *ud, uint8_t *b, size_t n) { nvpn_tunnel_t *t = (nvpn_tunnel_t *)ud; t->io.random(t->io.ud, b, n); }

int nvpn_tunnel_roster_changed(nvpn_tunnel_t *t) {
    char net[NVPN_MAX_NETID + 1];
    if (!t || !t->roster) return NVPN_ERR_ARG;
    if (nvpn_normalize_network_id(t->roster->network_id, net, sizeof net) < 0) return NVPN_ERR_ROSTER;
    if (nvpn_derive_tunnel_ip(net, t->self_pk, t->self_ip) != NVPN_OK) return NVPN_ERR_ROSTER;
    if (!nvpn_roster_is_member(t->roster, t->self_pk)) return NVPN_ERR_POLICY;
    return NVPN_OK;
}

int nvpn_tunnel_init(nvpn_tunnel_t *t, const nvpn_tunnel_io_t *io, const uint8_t secret[32],
                     const uint8_t upstream_xonly[32], const nvpn_roster_t *roster) {
    fips_io_t fio;
    int rc;
    if (!t || !io || !io->send || !io->random || !secret || !upstream_xonly || !roster) return NVPN_ERR_ARG;
    memset(t, 0, sizeof *t);
    t->io = *io; t->roster = roster;
    if ((rc = nvpn_pubkey_from_secret(secret, t->self_pk)) != NVPN_OK) return rc;
    if ((rc = nvpn_tunnel_roster_changed(t)) != NVPN_OK) return rc;
    memset(&fio, 0, sizeof fio);
    fio.send = fips_tx; fio.random = fips_rnd; fio.ud = t;
    fio.accept_peer = on_accept; fio.on_packet = on_packet;
    return fips_init(&t->fips, &fio, secret, upstream_xonly) == FIPS_OK ? NVPN_OK : NVPN_ERR_ARG;
}

int nvpn_tunnel_start(nvpn_tunnel_t *t, uint64_t now) { return fips_connect(&t->fips, now); }
int nvpn_tunnel_up(const nvpn_tunnel_t *t) { return fips_link_state(&t->fips) == FIPS_LINK_UP; }
void nvpn_tunnel_ip(const nvpn_tunnel_t *t, uint8_t ip[4]) { memcpy(ip, t->self_ip, 4); }

static void hold(nvpn_tunnel_t *t, const uint8_t peer[32], const uint8_t *pkt, size_t len, uint64_t now) {
    int i, slot = -1;
    for (i = 0; i < NVPN_TUNNEL_PENDING; i++) {
        if (t->pend[i].len && memcmp(t->pend[i].peer, peer, 32) == 0) { slot = i; break; }   /* newest packet per peer wins */
        if (!t->pend[i].len && slot < 0) slot = i;
    }
    if (slot < 0) { t->stats.tx_dropped++; return; }
    memcpy(t->pend[slot].peer, peer, 32); memcpy(t->pend[slot].pkt, pkt, len);
    t->pend[slot].len = (uint16_t)len; t->pend[slot].t_ms = now;
    t->stats.tx_queued++;
}

int nvpn_tunnel_output(nvpn_tunnel_t *t, const uint8_t *pkt, size_t len, uint64_t now) {
    uint8_t peer[NVPN_PUBKEY_LEN];
    if (!t || !pkt || len == 0 || len > FIPS_MAX_PACKET) { if (t) t->stats.tx_dropped++; return -1; }
    if (len >= 20 && pkt[9] != 1) {
        memcpy(t->stats.last_tx_src, pkt + 12, 4); memcpy(t->stats.last_tx_dst, pkt + 16, 4);
        t->stats.last_tx_proto = pkt[9]; t->stats.last_tx_len = (uint16_t)len;
    }
    if (!nvpn_route_outbound(t->roster, pkt, len, peer) || memcmp(peer, t->self_pk, 32) == 0) { t->stats.tx_dropped++; return -2; }
    if (!nvpn_tunnel_up(t)) { t->stats.tx_dropped++; return -3; }
    if (fips_session_ready(&t->fips, peer)) {
        if (fips_send_packet(&t->fips, peer, pkt, len, now) == FIPS_OK) { t->stats.tx_pkts++; return 1; }
        t->stats.tx_dropped++; return -4;
    }
    if (fips_session_open(&t->fips, peer, now) < 0) { t->stats.tx_dropped++; return -5; }
    hold(t, peer, pkt, len, now);
    return 0;
}

static void flush(nvpn_tunnel_t *t, uint64_t now) {
    int i;
    for (i = 0; i < NVPN_TUNNEL_PENDING; i++) {
        nvpn_tunnel_pending_t *p = &t->pend[i];
        if (!p->len) continue;
        if (fips_session_ready(&t->fips, p->peer)) {
            if (fips_send_packet(&t->fips, p->peer, p->pkt, p->len, now) == FIPS_OK) t->stats.tx_pkts++; else t->stats.tx_dropped++;
            p->len = 0;
        } else if (now - p->t_ms > PENDING_MAX_AGE_MS) { p->len = 0; t->stats.tx_dropped++; }
    }
}

int nvpn_tunnel_input(nvpn_tunnel_t *t, const uint8_t *d, size_t n, uint64_t now) {
    int rc; t->now_ms = now;
    rc = fips_input(&t->fips, d, n, now);
    t->stats.udp_rx++;
    if (rc != FIPS_OK) t->stats.last_input_rc = rc;
    flush(t, now);
    return rc;
}

void nvpn_tunnel_tick(nvpn_tunnel_t *t, uint64_t now) {
    t->now_ms = now;
    fips_tick(&t->fips, now);
    t->stats.link_state = (uint32_t)fips_link_state(&t->fips);
    t->stats.link_resends = t->fips.link.resends;
    t->stats.tree_depth = t->fips.up_anc_n;
    { int i; t->stats.lookups_active = 0; t->stats.sessions_up = 0;
      for (i = 0; i < FIPS_MAX_LOOKUPS; i++) t->stats.lookups_active += t->fips.lk[i].active;
      for (i = 0; i < FIPS_MAX_SESSIONS; i++) t->stats.sessions_up += t->fips.sess[i].state == 2; }
    memcpy(t->stats.dg, t->fips.diag, sizeof t->stats.dg);
    flush(t, now);
}
