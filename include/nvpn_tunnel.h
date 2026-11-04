/*
 * nvpn_tunnel — sans-IO virtual LAN endpoint (nostr-vpn compatible IPv4 mesh) for ESP32.
 *
 * Glue between an IP stack and the FIPS leaf node:
 *   outbound IPv4 packet (10.44.x.y)  -> roster lookup -> FSP session -> EndpointData (0x15)
 *   inbound EndpointData packet       -> roster admission (src/dst IP check) -> deliver to IP stack
 * Sessions are opened on demand; the first packets to a new peer are held briefly (1 per peer).
 * Also accepts sessions started by roster members. No heap, no threads: serialise calls yourself.
 */
#ifndef NVPN_TUNNEL_H
#define NVPN_TUNNEL_H

#include "fips.h"
#include "nvpn.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NVPN_TUNNEL_PENDING
#define NVPN_TUNNEL_PENDING 2      /* packets held while a session to a new peer is being set up */
#endif

typedef struct {
    void (*send)(void *ud, const uint8_t *dgram, size_t len);        /* UDP datagram to the upstream FIPS node */
    void (*random)(void *ud, uint8_t *buf, size_t n);                /* CSPRNG */
    void (*deliver)(void *ud, const uint8_t *ip_pkt, size_t len);    /* admitted inbound IPv4 packet -> IP stack */
    void *ud;
} nvpn_tunnel_io_t;

typedef struct {
    uint32_t tx_pkts, rx_pkts, tx_queued, tx_dropped, rx_rejected;
    /* link-level diagnostics (UDP datagrams to/from the upstream node) */
    uint32_t udp_tx, udp_tx_err, udp_rx;
    int32_t last_input_rc;         /* last non-zero fips_input() result (see fips_err_t), 0 = none */
    uint32_t link_state, link_resends; /* fips_link_state_t, msg1 resends in the current attempt */
    uint32_t tree_depth;           /* entries in the upstream's ancestry (0 = its TreeAnnounce not received yet) */
    uint32_t lookups_active, sessions_up;
    uint32_t dg[FIPS_DG_N];        /* fips diagnostic counters (see fips.h) */
    /* header of the last non-ICMP packet we sent / the last inbound packet rejected by the admission filter
       (src[4], dst[4], proto, len) - for diagnosing wrong source-address selection etc. */
    uint8_t last_tx_src[4], last_tx_dst[4], last_tx_proto; uint16_t last_tx_len;
    uint8_t last_rej_src[4], last_rej_dst[4], last_rej_proto; uint16_t last_rej_len;
    uint8_t last_rej_head[24];     /* first bytes of the last rejected frame (to identify non-IPv4 control frames) */
    uint32_t rej_not_ipv4;         /* rejected frames whose first byte is not an IPv4 header */
    uint32_t ctrl_ping_rx, ctrl_pong_tx, ctrl_other_rx;   /* nostr-vpn control frames (NVPN-FIPS-CTRL): pings answered / other kinds ignored */
} nvpn_tunnel_stats_t;

typedef struct {
    uint8_t peer[NVPN_PUBKEY_LEN];
    uint8_t pkt[FIPS_MAX_PACKET];
    uint16_t len;                  /* 0 = slot free */
    uint64_t t_ms;
} nvpn_tunnel_pending_t;

typedef struct {
    nvpn_tunnel_io_t io;
    fips_t fips;
    const nvpn_roster_t *roster;   /* owned by the caller; may be updated in place (nvpn_roster_update) */
    uint8_t self_pk[NVPN_PUBKEY_LEN];
    uint8_t self_ip[4];
    nvpn_tunnel_pending_t pend[NVPN_TUNNEL_PENDING];
    uint64_t now_ms;               /* time of the call being processed (for replies sent from callbacks) */
    nvpn_tunnel_stats_t stats;
} nvpn_tunnel_t;

/* Returns NVPN_OK; NVPN_ERR_POLICY if we are not in the roster. `roster` must outlive the tunnel. */
int nvpn_tunnel_init(nvpn_tunnel_t *t, const nvpn_tunnel_io_t *io, const uint8_t secret[32],
                     const uint8_t upstream_xonly[32], const nvpn_roster_t *roster);
/* Re-derive our mesh IP after the roster object changed. */
int nvpn_tunnel_roster_changed(nvpn_tunnel_t *t);
int nvpn_tunnel_start(nvpn_tunnel_t *t, uint64_t now_ms);
/* Feed one UDP datagram received from the upstream node. */
int nvpn_tunnel_input(nvpn_tunnel_t *t, const uint8_t *dgram, size_t len, uint64_t now_ms);
/* Call every <= 250 ms. */
void nvpn_tunnel_tick(nvpn_tunnel_t *t, uint64_t now_ms);
/* Send a raw IPv4 packet from the local IP stack into the mesh.
 * Returns 1 sent, 0 queued (session being set up), <0 dropped (not a member / link down / too big). */
int nvpn_tunnel_output(nvpn_tunnel_t *t, const uint8_t *ip_pkt, size_t len, uint64_t now_ms);
int nvpn_tunnel_up(const nvpn_tunnel_t *t);
void nvpn_tunnel_ip(const nvpn_tunnel_t *t, uint8_t ip_out[4]);

#ifdef __cplusplus
}
#endif
#endif
