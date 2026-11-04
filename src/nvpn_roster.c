#include "nvpn_internal.h"

static int in_list(const uint8_t (*arr)[32], size_t n, const uint8_t pk[32]) {
    size_t i;
    for (i = 0; i < n; i++) if (!memcmp(arr[i], pk, 32)) return 1;
    return 0;
}

int nvpn_roster_is_admin(const nvpn_roster_t *r, const uint8_t pk[NVPN_PUBKEY_LEN]) {
    return r && pk && in_list(r->admins, r->n_admins, pk);
}

int nvpn_roster_is_member(const nvpn_roster_t *r, const uint8_t pk[NVPN_PUBKEY_LEN]) {
    return r && pk && (in_list(r->devices, r->n_devices, pk) || in_list(r->admins, r->n_admins, pk));
}

int nvpn_roster_check_fresh(const nvpn_roster_t *r, uint64_t now) {
    if (!r) return NVPN_ERR_ARG;
    if (r->signed_at > now + NVPN_JOIN_ROSTER_MAX_FUTURE_SECS) return NVPN_ERR_FRESH;
    if (now > r->signed_at && now - r->signed_at > NVPN_JOIN_ROSTER_MAX_AGE_SECS) return NVPN_ERR_FRESH;
    return NVPN_OK;
}

static int same_network(const nvpn_roster_t *a, const nvpn_roster_t *b) {
    char x[NVPN_MAX_NETID + 9], y[NVPN_MAX_NETID + 9];
    if (nvpn_normalize_network_id(a->network_id, x, sizeof x) < 0) return 0;
    if (nvpn_normalize_network_id(b->network_id, y, sizeof y) < 0) return 0;
    return strcmp(x, y) == 0;
}

int nvpn_roster_update(nvpn_roster_t *cur, const nvpn_roster_t *in) {
    if (!cur || !in) return NVPN_ERR_ARG;
    if (!same_network(cur, in)) return NVPN_ERR_POLICY;
    if (!nvpn_roster_is_admin(cur, in->signer)) return NVPN_ERR_POLICY;
    if (in->signed_at <= cur->signed_at) return NVPN_ERR_STALE;
    *cur = *in;
    return NVPN_OK;
}

int nvpn_roster_bootstrap(nvpn_roster_t *cur, const nvpn_roster_t *in, const uint8_t trusted[NVPN_PUBKEY_LEN]) {
    if (!cur || !in || !trusted) return NVPN_ERR_ARG;
    if (memcmp(in->signer, trusted, 32) != 0 || !nvpn_roster_is_admin(in, trusted)) return NVPN_ERR_POLICY;
    *cur = *in;
    return NVPN_OK;
}

int nvpn_roster_lookup_ip(const nvpn_roster_t *r, const uint8_t ip[4], uint8_t pk_out[NVPN_PUBKEY_LEN]) {
    size_t i, n;
    if (!r || !ip) return -1;
    n = (size_t)r->n_devices + r->n_admins;
    for (i = 0; i < n; i++) {
        if (memcmp(r->ips[i], ip, 4) == 0) {
            if (pk_out) memcpy(pk_out, i < r->n_devices ? r->devices[i] : r->admins[i - r->n_devices], 32);
            return (int)i;
        }
    }
    return -1;
}

/* Minimal IPv4 header validation; returns header length or 0. */
static size_t ipv4_hdr(const uint8_t *p, size_t len) {
    size_t ihl, total;
    if (!p || len < 20 || (p[0] >> 4) != 4) return 0;
    ihl = (size_t)(p[0] & 15) * 4;
    total = ((size_t)p[2] << 8) | p[3];
    if (ihl < 20 || total < ihl || total > len) return 0;
    return ihl;
}

int nvpn_admit_inbound(const nvpn_roster_t *r, const uint8_t peer[NVPN_PUBKEY_LEN], const uint8_t self_ip[4],
                       const uint8_t *pkt, size_t len) {
    uint8_t expect[4];
    if (!r || !peer || !self_ip || !ipv4_hdr(pkt, len)) return 0;
    if (!nvpn_roster_is_member(r, peer)) return 0;
    if (nvpn_derive_tunnel_ip(r->network_id, peer, expect) != NVPN_OK) return 0;
    if (memcmp(pkt + 12, expect, 4) != 0) return 0;  /* source must be the peer's own address */
    if (memcmp(pkt + 16, self_ip, 4) != 0) return 0; /* destination must be us */
    return 1;
}

int nvpn_route_outbound(const nvpn_roster_t *r, const uint8_t *pkt, size_t len, uint8_t peer_out[NVPN_PUBKEY_LEN]) {
    if (!r || !ipv4_hdr(pkt, len)) return 0;
    if (pkt[16] != 10 || pkt[17] != 44) return 0;
    return nvpn_roster_lookup_ip(r, pkt + 16, peer_out) >= 0;
}
