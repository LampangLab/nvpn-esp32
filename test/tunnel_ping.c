#define _DEFAULT_SOURCE 1
/* Interop test: ICMP ping through the nostr-vpn virtual LAN.
 *   tunnel_ping <my_secret_hex> <peer pubkey hex|npub> <host:port> [secs] [listen|-] [upstream pubkey hex|npub]
 * By default the peer is both the upstream FIPS node and the only other roster member (test/interop-rs echo node).
 * With an upstream argument, <host:port> is that upstream (a seed) and the peer is reached through it over the mesh. */
#include "nvpn_tunnel.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int g_sock; static struct sockaddr_storage g_peer; static socklen_t g_peerlen;
static int g_got_reply, g_listen, g_keep, g_replies; static uint8_t g_expect_src[4];
static uint64_t now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000; }
static void tx(void *ud, const uint8_t *p, size_t n) { (void)ud; sendto(g_sock, p, n, 0, (struct sockaddr *)&g_peer, g_peerlen); }
static void rnd(void *ud, uint8_t *b, size_t n) { FILE *f = fopen("/dev/urandom", "rb"); (void)ud; if (!f || fread(b, 1, n, f) != n) abort(); fclose(f); }
static uint16_t csum(const uint8_t *d, size_t n) { uint32_t s = 0; size_t i; for (i = 0; i + 1 < n; i += 2) s += (uint32_t)(d[i] << 8 | d[i + 1]); if (n & 1) s += (uint32_t)d[n - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }
static void deliver(void *ud, const uint8_t *p, size_t n) {
    (void)ud;
    printf("DELIVER %zu bytes: src %u.%u.%u.%u proto %u icmp type %u\n", n, p[12], p[13], p[14], p[15], p[9], p[20]);
    if (n >= 28 && p[9] == 1 && (p[20] == 0 || (g_listen && p[20] == 8)) && memcmp(p + 12, g_expect_src, 4) == 0 && csum(p + 20, n - 20) == 0) { g_got_reply = 1; g_replies++; }
    fflush(stdout);
}

int main(int argc, char **argv) {
    static nvpn_tunnel_t t; static nvpn_roster_t r;
    nvpn_tunnel_io_t io = {tx, rnd, deliver, NULL};
    uint8_t sk[32], me[32], peer[32], upstream[32], peer_ip[4]; char host[128], *colon; int secs = 10, last = -1, sent = 0;
    struct addrinfo hints = {0}, *res; uint64_t t0, now, last_ping = 0;
    if (argc == 3 && !strcmp(argv[1], "--npub")) {   /* print the npub of a secret */
        uint8_t k[32], pk[32]; char np[100];
        if (nvpn_hex_decode(argv[2], strlen(argv[2]), k, 32) || nvpn_pubkey_from_secret(k, pk) || nvpn_pubkey_to_npub(pk, np, sizeof np)) return 2;
        puts(np); return 0;
    }
    if (argc < 4) { fprintf(stderr, "usage: %s <secret_hex> <peer hex|npub> <host:port> [secs]\n", argv[0]); return 2; }
    if (nvpn_hex_decode(argv[1], strlen(argv[1]), sk, 32) || nvpn_pubkey_parse(argv[2], peer)) { fprintf(stderr, "bad key\n"); return 2; }
    strncpy(host, argv[3], sizeof host - 1); colon = strrchr(host, ':'); if (!colon) return 2; *colon++ = 0;
    if (argc > 4) secs = atoi(argv[4]);
    if (argc > 5 && !strcmp(argv[5], "listen")) g_listen = 1;
    memcpy(upstream, peer, 32);
    if (argc > 6 && nvpn_pubkey_parse(argv[6], upstream)) { fprintf(stderr, "bad upstream key\n"); return 2; }   /* wait for a peer-initiated packet instead of pinging */
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, colon, &hints, &res)) return 2;
    memcpy(&g_peer, res->ai_addr, res->ai_addrlen); g_peerlen = res->ai_addrlen;
    g_sock = socket(res->ai_family, SOCK_DGRAM, 0);
    freeaddrinfo(res);

    nvpn_pubkey_from_secret(sk, me);
    strcpy(r.network_id, "testnet"); strcpy(r.name, "test");
    memcpy(r.devices[0], me, 32); memcpy(r.devices[1], peer, 32); r.n_devices = 2;
    nvpn_derive_tunnel_ip(r.network_id, me, r.ips[0]); nvpn_derive_tunnel_ip(r.network_id, peer, r.ips[1]);
    memcpy(peer_ip, r.ips[1], 4); memcpy(g_expect_src, peer_ip, 4);
    printf("my ip %u.%u.%u.%u  peer ip %u.%u.%u.%u\n", r.ips[0][0], r.ips[0][1], r.ips[0][2], r.ips[0][3], peer_ip[0], peer_ip[1], peer_ip[2], peer_ip[3]);

    if (nvpn_tunnel_init(&t, &io, sk, upstream, &r) != NVPN_OK) { fprintf(stderr, "tunnel init failed\n"); return 1; }
    if (getenv("NVPN_NO_CLIENT")) {                /* 0 normal, 1 negotiation off (TreeAnnounce), 2 upstream never answers (role 3), 3 same but legacy router fallback */
        int m = atoi(getenv("NVPN_NO_CLIENT"));
        t.fips.client_role_off = (uint8_t)(m == 3 ? 2 : m);
        t.fips.allow_router_fallback = (uint8_t)(m == 3);
    }
    t0 = now = now_ms();
    nvpn_tunnel_start(&t, now);
    g_keep = getenv("KEEP") != NULL;            /* KEEP=1: keep pinging until the time is up and count the replies */
    while ((g_keep || !g_got_reply) && (now = now_ms()) - t0 < (uint64_t)secs * 1000) {
        fd_set fs; struct timeval tv = {0, 50000}; uint8_t buf[2048]; ssize_t n;
        FD_ZERO(&fs); FD_SET(g_sock, &fs);
        if (select(g_sock + 1, &fs, NULL, NULL, &tv) > 0 && (n = recv(g_sock, buf, sizeof buf, 0)) > 0) nvpn_tunnel_input(&t, buf, (size_t)n, now_ms());
        nvpn_tunnel_tick(&t, now_ms());
        if (nvpn_tunnel_up(&t) != last) { last = nvpn_tunnel_up(&t); printf("link up=%d\n", last); fflush(stdout); }
        if (!g_listen && nvpn_tunnel_up(&t) && now_ms() - last_ping > 1000) {
            uint8_t p[60] = {0x45, 0, 0, 60, 0, (uint8_t)sent, 0, 0, 64, 1, 0, 0};
            uint16_t c;
            memcpy(p + 12, r.ips[0], 4); memcpy(p + 16, peer_ip, 4);
            c = csum(p, 20); p[10] = (uint8_t)(c >> 8); p[11] = (uint8_t)c;
            p[20] = 8; p[22] = 0; p[23] = 0; p[24] = 0x12; p[25] = 0x34; p[26] = 0; p[27] = (uint8_t)sent;
            memset(p + 28, 0xab, 32);
            c = csum(p + 20, 40); p[22] = (uint8_t)(c >> 8); p[23] = (uint8_t)c;
            printf("ping #%d -> rc=%d\n", sent, nvpn_tunnel_output(&t, p, sizeof p, now_ms())); fflush(stdout);
            sent++; last_ping = now_ms();
        }
    }
    if (g_keep) printf("replies: %d / pings sent: %d\n", g_replies, sent);
    printf("CTRL: ping_rx=%u pong_tx=%u other=%u\n", t.stats.ctrl_ping_rx, t.stats.ctrl_pong_tx, t.stats.ctrl_other_rx);
    printf("RR_TX: %u\n", t.fips.diag[FIPS_DG_RR_TX]);
    printf("ROLE: %s\n", t.fips.role == 1 ? "client-only (ClientOnly sent)" : t.fips.role == 2 ? "fallback (TreeAnnounce)" : t.fips.role == 3 ? "waiting (upstream lacks leaf support)" : "negotiating");
    { fips_trace_t e; uint32_t i; for (i = 0; fips_trace_get(&t.fips, i, &e) || i < t.fips.trace_n; i++) if (fips_trace_get(&t.fips, i, &e)) printf("TRACE %u t=%u kind=%u arg=%u tx=%u rx=%u\n", i, e.t_ms, e.kind, e.arg, e.tx, e.rx); }
    printf("RESULT: %s (tx %u rx %u queued %u dropped %u rejected %u)\n", g_got_reply ? (g_listen ? "INBOUND OK" : "PING OK") : "NO REPLY",
           t.stats.tx_pkts, t.stats.rx_pkts, t.stats.tx_queued, t.stats.tx_dropped, t.stats.rx_rejected);
    fips_disconnect(&t.fips, now_ms());
    return g_got_reply ? 0 : 1;
}
