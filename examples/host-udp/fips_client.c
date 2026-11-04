#define _DEFAULT_SOURCE 1
/* Host (Linux/macOS) demo client: speaks FIPS to an upstream node over UDP using the same
 * library code that runs on the ESP32. Handy for interop testing against the Rust `fips` daemon.
 *
 *   fips_client <my_secret_hex> <upstream_pubkey hex|npub> <host:port> [seconds] [dest_pubkey port "message"]
 */
#include "fips.h"
#include "nvpn.h"
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
static uint64_t now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000; }
static void tx(void *ud, const uint8_t *p, size_t n) { (void)ud; sendto(g_sock, p, n, 0, (struct sockaddr *)&g_peer, g_peerlen); }
static void rnd(void *ud, uint8_t *b, size_t n) { FILE *f = fopen("/dev/urandom", "rb"); (void)ud; if (!f || fread(b, 1, n, f) != n) abort(); fclose(f); }
static void on_data(void *ud, const uint8_t src[16], uint16_t sp, uint16_t dp, const uint8_t *p, size_t n) {
    char hex[33]; (void)ud; nvpn_hex_encode(src, 16, hex);
    printf("DATA from %s port %u->%u (%zu bytes): %.*s\n", hex, sp, dp, n, (int)n, (const char *)p); fflush(stdout);
}

int main(int argc, char **argv) {
    static fips_t node; fips_io_t io = {tx, rnd, on_data, NULL};
    uint8_t sk[32], up[32], dest[32]; char host[128], *colon; int secs = 10, have_dest = 0, last_state = -1, sent = 0;
    uint64_t t0, now; struct addrinfo hints = {0}, *res;
    if (argc < 4) { fprintf(stderr, "usage: %s <secret_hex> <upstream hex|npub> <host:port> [secs] [dest port msg]\n", argv[0]); return 2; }
    if (nvpn_hex_decode(argv[1], strlen(argv[1]), sk, 32) || nvpn_pubkey_parse(argv[2], up)) { fprintf(stderr, "bad key\n"); return 2; }
    strncpy(host, argv[3], sizeof host - 1); colon = strrchr(host, ':'); if (!colon) return 2; *colon++ = 0;
    if (argc > 4) secs = atoi(argv[4]);
    if (argc > 7) { if (nvpn_pubkey_parse(argv[5], dest)) return 2; have_dest = 1; }
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, colon, &hints, &res)) { fprintf(stderr, "resolve failed\n"); return 2; }
    memcpy(&g_peer, res->ai_addr, res->ai_addrlen); g_peerlen = res->ai_addrlen;
    g_sock = socket(res->ai_family, SOCK_DGRAM, 0);
    { uint8_t me[32]; char hx[65]; nvpn_pubkey_from_secret(sk, me); nvpn_hex_encode(me, 32, hx); printf("me: %s\n", hx); }
    if (fips_init(&node, &io, sk, up) != FIPS_OK) return 1;
    t0 = now = now_ms();
    fips_connect(&node, now);
    while ((now = now_ms()) - t0 < (uint64_t)secs * 1000) {
        fd_set fs; struct timeval tv = {0, 100000}; uint8_t buf[2048]; ssize_t n;
        FD_ZERO(&fs); FD_SET(g_sock, &fs);
        if (select(g_sock + 1, &fs, NULL, NULL, &tv) > 0 && (n = recv(g_sock, buf, sizeof buf, 0)) > 0) {
            int rc = fips_input(&node, buf, (size_t)n, now_ms());
            if (rc) printf("input rc=%d (%zd bytes)\n", rc, n);
        }
        fips_tick(&node, now_ms());
        if (fips_link_state(&node) != last_state) { last_state = fips_link_state(&node); printf("link state -> %d\n", last_state); fflush(stdout); }
        if (have_dest && fips_link_state(&node) == FIPS_LINK_UP) {
            if (!sent && fips_session_open(&node, dest, now_ms()) >= 0) sent = 1;
            if (sent == 1 && fips_session_ready(&node, dest)) {
                if (fips_send_data(&node, dest, (uint16_t)atoi(argv[6]), (uint16_t)atoi(argv[6]), (const uint8_t *)argv[7], strlen(argv[7]), now_ms()) == FIPS_OK) { printf("session ready, sent data\n"); fflush(stdout); sent = 2; }
            }
        }
    }
    fips_disconnect(&node, now_ms());
    return last_state == FIPS_LINK_UP ? 0 : 1;
}
