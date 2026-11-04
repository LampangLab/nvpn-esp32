/*
 * nvpn_netif — ESP32 (ESP-IDF / Arduino-ESP32) lwIP integration: turns the nvpn tunnel into a real
 * network interface "nv0" with the node's mesh IP (10.44.x.y/16). After nvpn_netif_start() ordinary
 * BSD sockets (UDP/TCP), ping, HTTP, MQTT brokers/clients etc. work to other roster members' mesh IPs.
 * Wi-Fi/Ethernet must already be up (IP connectivity to the upstream FIPS node's UDP endpoint).
 */
#ifndef NVPN_NETIF_H
#define NVPN_NETIF_H

#include "nvpn_tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *upstream_host;                    /* IP or DNS name of the upstream FIPS node */
    uint16_t upstream_port;                       /* its UDP port (default FIPS port 2121) */
    uint8_t upstream_pubkey[NVPN_PUBKEY_LEN];     /* its x-only public key */
    uint8_t secret[32];                           /* our Nostr secret key */
    const nvpn_roster_t *roster;                  /* verified roster; must outlive the netif */
    int task_stack;                               /* 0 = default (8192) */
    int task_priority;                            /* 0 = default (5) */
} nvpn_netif_cfg_t;

/* Returns 0 on success, negative on failure. Creates the UDP socket, the lwIP netif and a worker task. */
int nvpn_netif_start(const nvpn_netif_cfg_t *cfg);
/* 1 once the FIPS link to the upstream is up. */
int nvpn_netif_link_up(void);
/* Our mesh IPv4 address (network order). */
void nvpn_netif_ip(uint8_t ip[4]);
/* Call after the roster object was updated in place (nvpn_roster_update); re-derives our IP. */
int nvpn_netif_roster_changed(void);
void nvpn_netif_stats(nvpn_tunnel_stats_t *out);
/* Rekey/role trace (see fips.h FIPS_TR_*): copies event number idx (absolute, see *total) into *out; returns 1 if it is still
 * stored, else 0. *total = events recorded so far; *role = 0 negotiating, 1 client-only, 2 TreeAnnounce fallback. */
int nvpn_netif_trace(uint32_t idx, fips_trace_t *out, uint32_t *total, uint8_t *role);

#ifdef __cplusplus
}
#endif
#endif
