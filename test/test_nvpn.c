/* Host tests: every expected value comes from the Rust reference (vectors.h). */
#include "nvpn.h"
#include "vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void unhex(const char *h, uint8_t *o, size_t n) { if (nvpn_hex_decode(h, strlen(h), o, n)) { printf("bad hex\n"); exit(2); } }
static nvpn_roster_t R[32];
static int rc_of[32];

static int err_code(const char *e) {
    if (!strcmp(e, "ID")) return NVPN_ERR_ID;
    if (!strcmp(e, "SIG")) return NVPN_ERR_SIG;
    if (!strcmp(e, "KIND")) return NVPN_ERR_KIND;
    if (!strcmp(e, "CONTENT")) return NVPN_ERR_CONTENT;
    if (!strcmp(e, "ROSTER")) return NVPN_ERR_ROSTER;
    if (!strcmp(e, "CAPACITY")) return NVPN_ERR_CAPACITY;
    return 999;
}

static const v_roster *find(const char *name, int *idx) {
    size_t i;
    for (i = 0; i < sizeof V_ROSTERS / sizeof *V_ROSTERS; i++)
        if (!strcmp(V_ROSTERS[i].name, name)) { *idx = (int)i; return &V_ROSTERS[i]; }
    printf("missing vector %s\n", name); exit(2);
}

static void t_sha_hex(void) {
    uint8_t d[32]; char h[65];
    nvpn_sha256((const uint8_t *)"abc", 3, d); nvpn_hex_encode(d, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256(abc)");
    nvpn_sha256((const uint8_t *)"", 0, d); nvpn_hex_encode(d, 32, h);
    CHECK(!strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256(empty)");
    { /* multi-block + padding boundary (56, 64, 119 bytes) */
        static const char *exp[] = {
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",  /* 56 x 'a' */
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"}; /* 64 x 'a' */
        char buf[128]; memset(buf, 'a', sizeof buf);
        nvpn_sha256((const uint8_t *)buf, 56, d); nvpn_hex_encode(d, 32, h); CHECK(!strcmp(h, exp[0]), "sha56 %s", h);
        nvpn_sha256((const uint8_t *)buf, 64, d); nvpn_hex_encode(d, 32, h); CHECK(!strcmp(h, exp[1]), "sha64 %s", h);
    }
}

static void t_netids(void) {
    size_t i; char out[128];
    for (i = 0; i < sizeof V_NETIDS / sizeof *V_NETIDS; i++) {
        int n = nvpn_normalize_network_id(V_NETIDS[i].in, out, sizeof out);
        CHECK(n >= 0 && !strcmp(out, V_NETIDS[i].out), "netid '%s' -> '%s' expected '%s'", V_NETIDS[i].in, out, V_NETIDS[i].out);
    }
}

static void t_keys_ips(void) {
    size_t i; uint8_t sk[32], pk[32], pk2[32]; char hex[65], npub[80];
    for (i = 0; i < sizeof V_KEYS / sizeof *V_KEYS; i++) {
        unhex(V_KEYS[i].sk, sk, 32);
        CHECK(nvpn_pubkey_from_secret(sk, pk) == NVPN_OK, "derive");
        nvpn_hex_encode(pk, 32, hex);
        CHECK(!strcmp(hex, V_KEYS[i].pk), "pubkey %zu %s", i, hex);
        CHECK(nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK && !strcmp(npub, V_KEYS[i].npub), "npub %s vs %s", npub, V_KEYS[i].npub);
        CHECK(nvpn_pubkey_parse(V_KEYS[i].npub, pk2) == NVPN_OK && !memcmp(pk, pk2, 32), "npub parse");
        { char up[80]; size_t k; for (k = 0; V_KEYS[i].npub[k]; k++) up[k] = (char)((V_KEYS[i].npub[k] >= 'a' && V_KEYS[i].npub[k] <= 'z') ? V_KEYS[i].npub[k] - 32 : V_KEYS[i].npub[k]); up[k] = 0;
          CHECK(nvpn_pubkey_parse(up, pk2) == NVPN_OK && !memcmp(pk, pk2, 32), "uppercase npub parse"); }
        CHECK(nvpn_pubkey_parse(V_KEYS[i].pk, pk2) == NVPN_OK && !memcmp(pk, pk2, 32), "hex parse");
    }
    { /* bad checksum / wrong length / mixed case */
        char bad[80]; strcpy(bad, V_KEYS[0].npub); bad[20] = bad[20] == 'q' ? 'p' : 'q';
        CHECK(nvpn_pubkey_parse(bad, pk2) != NVPN_OK, "bad checksum accepted");
        strcpy(bad, V_KEYS[0].npub); bad[8] = (char)(bad[8] >= 'a' && bad[8] <= 'z' ? bad[8] - 32 : bad[8]);
        CHECK(nvpn_pubkey_parse(bad, pk2) != NVPN_OK || (bad[8] >= '0' && bad[8] <= '9'), "mixed case accepted");
        CHECK(nvpn_pubkey_parse("abcd", pk2) != NVPN_OK, "short");
    }
    for (i = 0; i < sizeof V_IPS / sizeof *V_IPS; i++) {
        uint8_t ip[4]; char s[24];
        unhex(V_IPS[i].pk, pk, 32);
        CHECK(nvpn_derive_tunnel_ip(V_IPS[i].net, pk, ip) == NVPN_OK, "ip derive");
        snprintf(s, sizeof s, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        CHECK(!strcmp(s, V_IPS[i].ip), "ip %s %s: %s vs %s", V_IPS[i].net, V_IPS[i].pk, s, V_IPS[i].ip);
    }
}

static void t_labels(void) {
    size_t i; char out[64];
    for (i = 0; i < sizeof V_LABELS / sizeof *V_LABELS; i++) {
        size_t n = nvpn_dns_normalize_label(V_LABELS[i].in, out, sizeof out);
        if (V_LABELS[i].out) CHECK(n && !strcmp(out, V_LABELS[i].out), "label '%s' -> '%s' expected '%s'", V_LABELS[i].in, out, V_LABELS[i].out);
        else CHECK(n == 0, "label '%s' should be unusable, got '%s'", V_LABELS[i].in, out);
    }
}

static void t_rosters(void) {
    size_t i;
    for (i = 0; i < sizeof V_ROSTERS / sizeof *V_ROSTERS; i++) {
        const v_roster *v = &V_ROSTERS[i];
        int rc = nvpn_roster_verify(v->event, strlen(v->event), &R[i]);
        rc_of[i] = rc;
        if (!v->ok) { CHECK(rc == err_code(v->err), "%s: expected error %s got %d", v->name, v->err, rc); continue; }
        CHECK(rc == NVPN_OK, "%s: verify returned %d", v->name, rc);
        if (rc != NVPN_OK) continue;
        {
            char hex[65]; int k, j;
            CHECK(!strcmp(R[i].network_id, v->network_id), "%s: network id", v->name);
            CHECK(R[i].signed_at == v->signed_at, "%s: signed_at", v->name);
            nvpn_hex_encode(R[i].event_id, 32, hex); CHECK(!strcmp(hex, v->id), "%s: event id", v->name);
            if (v->net_name) CHECK(!strcmp(R[i].name, v->net_name), "%s: name '%s'", v->name, R[i].name);
            if (v->n_dev || v->n_adm) {
                CHECK(R[i].n_devices == v->n_dev, "%s: n_devices %d vs %d", v->name, R[i].n_devices, v->n_dev);
                CHECK(R[i].n_admins == v->n_adm, "%s: n_admins", v->name);
                for (k = 0; k < v->n_dev && k < R[i].n_devices; k++) { nvpn_hex_encode(R[i].devices[k], 32, hex); CHECK(!strcmp(hex, v->dev[k]), "%s: device %d order", v->name, k); }
                for (k = 0; k < v->n_adm && k < R[i].n_admins; k++) { nvpn_hex_encode(R[i].admins[k], 32, hex); CHECK(!strcmp(hex, v->adm[k]), "%s: admin %d", v->name, k); }
            }
            if (v->n_al >= 0) CHECK(R[i].n_aliases == v->n_al, "%s: n_aliases %d vs %d", v->name, R[i].n_aliases, v->n_al);
            for (k = 0; k < v->n_al; k++) {
                int found = 0;
                for (j = 0; j < R[i].n_aliases; j++) {
                    nvpn_hex_encode(R[i].aliases[j].pubkey, 32, hex);
                    if (!strcmp(hex, v->al[k][0])) { found = 1; CHECK(!strcmp(R[i].aliases[j].alias, v->al[k][1]), "%s: alias '%s' vs '%s'", v->name, R[i].aliases[j].alias, v->al[k][1]); }
                }
                CHECK(found, "%s: alias key missing", v->name);
            }
        }
    }
    { /* escapes roster: alias/name with quotes, control chars, emoji must round-trip byte-exact */
        int idx; const v_roster *v = find("escapes", &idx);
        CHECK(rc_of[idx] == NVPN_OK && R[idx].n_aliases == 1, "escapes parsed");
        CHECK(strstr(R[idx].aliases[0].alias, "\xF0\x9F\x98\x80") != NULL, "emoji alias");
        (void)v;
    }
    { /* truncated / garbage input must fail cleanly at every prefix */
        int idx; const v_roster *v = find("basic", &idx); size_t n = strlen(v->event), k; nvpn_roster_t tmp;
        for (k = 0; k < n; k++) CHECK(nvpn_roster_verify(v->event, k, &tmp) != NVPN_OK, "prefix %zu accepted", k);
        CHECK(nvpn_roster_verify("", 0, &tmp) != NVPN_OK, "empty");
        CHECK(nvpn_roster_verify("{}", 2, &tmp) != NVPN_OK, "{}");
        CHECK(nvpn_roster_verify(NULL, 0, &tmp) == NVPN_ERR_ARG, "null");
    }
    { /* every single-byte mutation of a valid event must be rejected or parse to the identical roster */
        int idx; const v_roster *v = find("basic", &idx); size_t n = strlen(v->event), k; char *m = malloc(n + 1); nvpn_roster_t tmp; int accepted = 0;
        for (k = 0; k < n; k++) {
            memcpy(m, v->event, n + 1); m[k] = (char)(m[k] ^ 0x01);
            if (nvpn_roster_verify(m, n, &tmp) == NVPN_OK) { accepted++; CHECK(!memcmp(tmp.event_id, R[idx].event_id, 32) && tmp.n_devices == R[idx].n_devices, "mutation %zu accepted with different content", k); }
        }
        free(m); (void)accepted;
    }
}

static void t_policy(void) {
    int ib, in, ir, ie; const v_roster *vb = find("basic", &ib), *vn = find("newer", &in), *vr = find("rogue", &ir), *ve = find("escapes", &ie);
    nvpn_roster_t cur; uint8_t admin[32], other[32];
    (void)vb; (void)vn; (void)vr; (void)ve;
    unhex(V_KEYS[0].pk, admin, 32); unhex(V_KEYS[5].pk, other, 32); /* key 5 only appears in the rogue roster */
    CHECK(nvpn_roster_bootstrap(&cur, &R[ib], other) == NVPN_ERR_POLICY, "bootstrap with untrusted admin");
    CHECK(nvpn_roster_bootstrap(&cur, &R[ib], admin) == NVPN_OK, "bootstrap");
    CHECK(nvpn_roster_update(&cur, &R[ib]) == NVPN_ERR_STALE, "same roster is stale");
    CHECK(nvpn_roster_update(&cur, &R[ir]) == NVPN_ERR_POLICY, "non-admin signer rejected");
    CHECK(nvpn_roster_update(&cur, &R[ie]) == NVPN_ERR_POLICY, "different network rejected");
    CHECK(nvpn_roster_update(&cur, &R[in]) == NVPN_OK && cur.signed_at == 1800000500ULL && cur.n_devices == 4, "newer accepted");
    CHECK(nvpn_roster_update(&cur, &R[ib]) == NVPN_ERR_STALE, "older rejected after update");
    CHECK(nvpn_roster_is_admin(&cur, admin) && nvpn_roster_is_member(&cur, admin), "admin membership");
    CHECK(!nvpn_roster_is_member(&cur, other), "non-member");
    CHECK(nvpn_roster_check_fresh(&R[ib], 1800000000ULL + 3600) == NVPN_OK, "fresh");
    CHECK(nvpn_roster_check_fresh(&R[ib], 1800000000ULL + NVPN_JOIN_ROSTER_MAX_AGE_SECS + 1) == NVPN_ERR_FRESH, "too old");
    CHECK(nvpn_roster_check_fresh(&R[ib], 1800000000ULL - NVPN_JOIN_ROSTER_MAX_FUTURE_SECS - 1) == NVPN_ERR_FRESH, "too far in future");
    CHECK(nvpn_roster_check_fresh(&R[ib], 1800000000ULL - NVPN_JOIN_ROSTER_MAX_FUTURE_SECS) == NVPN_OK, "future boundary");
}

static void ipv4(uint8_t *p, size_t total, const uint8_t *src, const uint8_t *dst) {
    memset(p, 0, total); p[0] = 0x45; p[2] = (uint8_t)(total >> 8); p[3] = (uint8_t)total; p[8] = 64; p[9] = 17;
    memcpy(p + 12, src, 4); memcpy(p + 16, dst, 4);
}

static void t_routing(void) {
    int ib; const v_roster *vb = find("basic", &ib); const nvpn_roster_t *r = &R[ib]; (void)vb;
    uint8_t pk1[32], pk2[32], ip1[4], ip2[4], self[4], pkt[40], peer[32], unknown_ip[4] = {10, 44, 0, 0};
    unhex(V_KEYS[1].pk, pk1, 32); unhex(V_KEYS[2].pk, pk2, 32);
    nvpn_derive_tunnel_ip("home", pk1, ip1); nvpn_derive_tunnel_ip("home", pk2, ip2);
    self[0] = 10; self[1] = 44; self[2] = 1; self[3] = 1;
    ipv4(pkt, 40, ip1, self);
    CHECK(nvpn_admit_inbound(r, pk1, self, pkt, 40) == 1, "legit inbound");
    CHECK(nvpn_admit_inbound(r, pk2, self, pkt, 40) == 0, "spoofed source (peer 2 claiming peer 1's IP)");
    ipv4(pkt, 40, ip1, ip2);
    CHECK(nvpn_admit_inbound(r, pk1, self, pkt, 40) == 0, "wrong destination");
    ipv4(pkt, 40, ip1, self);
    { uint8_t stranger[32]; unhex(V_KEYS[5].pk, stranger, 32); CHECK(nvpn_admit_inbound(r, stranger, self, pkt, 40) == 0, "non-member peer"); }
    pkt[0] = 0x65; CHECK(nvpn_admit_inbound(r, pk1, self, pkt, 40) == 0, "ipv6-looking packet"); pkt[0] = 0x45;
    CHECK(nvpn_admit_inbound(r, pk1, self, pkt, 39) == 0, "truncated packet");
    CHECK(nvpn_admit_inbound(r, pk1, self, pkt, 10) == 0, "tiny packet");
    ipv4(pkt, 40, self, ip2);
    CHECK(nvpn_route_outbound(r, pkt, 40, peer) == 1 && !memcmp(peer, pk2, 32), "outbound to peer 2");
    ipv4(pkt, 40, self, unknown_ip);
    CHECK(nvpn_route_outbound(r, pkt, 40, peer) == 0, "outbound to unknown mesh ip");
    { uint8_t pub[4] = {8, 8, 8, 8}; ipv4(pkt, 40, self, pub); CHECK(nvpn_route_outbound(r, pkt, 40, peer) == 0, "outbound to internet is not mesh"); }
}

static int u16at(const uint8_t *p) { return (p[0] << 8) | p[1]; }

static size_t mkq(uint8_t *q, const char *name, int qtype) {
    size_t o = 12; const char *p = name;
    memset(q, 0, 12); q[0] = 0xab; q[1] = 0xcd; q[2] = 0x01; q[5] = 1;
    while (*p) { const char *d = strchr(p, '.'); size_t l = d ? (size_t)(d - p) : strlen(p); q[o++] = (uint8_t)l; memcpy(q + o, p, l); o += l; p += l + (d ? 1 : 0); }
    q[o++] = 0; q[o++] = (uint8_t)(qtype >> 8); q[o++] = (uint8_t)qtype; q[o++] = 0; q[o++] = 1;
    return o;
}

static void t_dns(void) {
    int ib; const v_roster *vb = find("basic", &ib); const nvpn_roster_t *r = &R[ib]; (void)vb;
    uint8_t q[300], resp[512], ip1[4], pk1[32]; size_t ql; int n;
    unhex(V_KEYS[1].pk, pk1, 32); nvpn_derive_tunnel_ip("home", pk1, ip1);

    ql = mkq(q, "living-room.nvpn", 1);
    n = nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp);
    CHECK(n == (int)ql + 16, "A answer length %d", n);
    CHECK(resp[0] == 0xab && resp[1] == 0xcd && (resp[2] & 0x80) && (resp[2] & 0x04) && (resp[2] & 0x01), "flags QR/AA/RD");
    CHECK((resp[3] & 15) == 0 && u16at(resp + 4) == 1 && u16at(resp + 6) == 1, "rcode/counts");
    CHECK(!memcmp(resp + n - 4, ip1, 4) && u16at(resp + n - 14) == 1 && resp[n - 7] == 30, "answer ip/type/ttl");
    ql = mkq(q, "LIVING-room", 1);
    CHECK(nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp) > 0, "bare alias, case-insensitive");
    ql = mkq(q, "living-room.nvpn", 28); /* AAAA: known name -> NOERROR, no answer */
    n = nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp);
    CHECK(n == (int)ql && (resp[3] & 15) == 0 && u16at(resp + 6) == 0, "AAAA for known name is NODATA");
    ql = mkq(q, "nobody.nvpn", 1);
    CHECK(nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp) == 0, "unknown name not handled");
    n = nvpn_dns_respond(r, "nvpn", 1, q, ql, resp, sizeof resp);
    CHECK(n == (int)ql && (resp[3] & 15) == 3, "unknown name NXDOMAIN when asked");
    ql = mkq(q, "living-room.other", 1);
    CHECK(nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp) == 0, "wrong suffix");
    ql = mkq(q, "admin-box.nvpn", 1);
    CHECK(nvpn_dns_respond(r, ".NVPN.", 0, q, ql, resp, sizeof resp) > 0, "suffix normalisation + admin alias");
    CHECK(nvpn_dns_respond(r, "nvpn", 0, q, 5, resp, sizeof resp) == 0, "short packet ignored");
    ql = mkq(q, "esp32-sensor.nvpn", 1);
    CHECK(nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, ql + 3) == NVPN_ERR_BUF, "small output buffer");
    { uint8_t cp[2][4], p2[32]; uint8_t got[4]; unhex(V_KEYS[2].pk, p2, 32); (void)cp; nvpn_derive_tunnel_ip("home", p2, got);
      ql = mkq(q, "esp32-sensor.nvpn", 1); n = nvpn_dns_respond(r, "nvpn", 0, q, ql, resp, sizeof resp);
      CHECK(n > 0 && !memcmp(resp + n - 4, got, 4), "esp32-sensor resolves to its derived ip"); }
    { /* fuzz: random garbage must never crash or overrun */
        uint8_t g[512]; int it, k; unsigned s = 12345;
        for (it = 0; it < 20000; it++) {
            size_t gl = (size_t)(s = s * 1103515245u + 12345u) % 300;
            for (k = 0; k < (int)gl; k++) g[k] = (uint8_t)((s = s * 1103515245u + 12345u) >> 16);
            if (gl > 12 && it % 2) { g[2] &= 0x7f; g[4] = 0; g[5] = 1; }
            (void)nvpn_dns_respond(r, "nvpn", 1, g, gl, resp, sizeof resp);
        }
    }
}

static void t_schnorr(void) {
    uint8_t pk[32], msg[32], sig[64], sk[32], aux[32] = {1}, sig2[64]; 
    unhex(V_SCHNORR[0], pk, 32); unhex(V_SCHNORR[1], msg, 32); unhex(V_SCHNORR[2], sig, 64);
    CHECK(nvpn_schnorr_verify(pk, msg, sig) == NVPN_OK, "verify Rust-made signature");
    msg[0] ^= 1; CHECK(nvpn_schnorr_verify(pk, msg, sig) == NVPN_ERR_SIG, "wrong message"); msg[0] ^= 1;
    unhex(V_KEYS[0].sk, sk, 32);
    CHECK(nvpn_schnorr_sign(sk, msg, aux, sig2) == NVPN_OK && nvpn_schnorr_verify(pk, msg, sig2) == NVPN_OK, "sign+verify");
    CHECK(nvpn_secp_randomize(aux) == NVPN_OK, "randomize");
    CHECK(nvpn_schnorr_sign(sk, msg, NULL, sig2) == NVPN_OK && nvpn_schnorr_verify(pk, msg, sig2) == NVPN_OK, "sign after randomize");
    { uint8_t zero[32] = {0}, out[32]; CHECK(nvpn_pubkey_from_secret(zero, out) != NVPN_OK, "zero secret rejected"); }
}

int main(void) {
    t_sha_hex(); t_netids(); t_keys_ips(); t_labels(); t_rosters(); t_policy(); t_routing(); t_dns(); t_schnorr();
    printf("%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
