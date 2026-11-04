/* MagicDNS: answers A queries for roster aliases. Wire handling is a small
 * RFC 1035 subset (uncompressed question names, as sent by stub resolvers). */
#include "nvpn_internal.h"

#define DNS_TTL 30

size_t nvpn_dns_normalize_label(const char *in, char *out, size_t cap) {
    size_t n = 0;
    int prev_dash = 0;
    if (!in || !out || cap < 64) return 0;
    for (; *in && n < 63; in++) {
        unsigned char c = (unsigned char)*in;
        if ((c & 0xC0) == 0x80) continue; /* UTF-8 continuation: part of the previous char */
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) { out[n++] = (char)c; prev_dash = 0; }
        else if (c >= 'A' && c <= 'Z') { out[n++] = (char)(c + 32); prev_dash = 0; }
        else if (!prev_dash) { if (n) out[n++] = '-'; prev_dash = 1; } /* leading '-' dropped */
    }
    while (n && out[n - 1] == '-') n--;
    out[n] = 0;
    return n;
}

static int eq_ci(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char x = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char y = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (x != y) return 0;
    }
    return *a == *b;
}

int nvpn_dns_lookup(const nvpn_roster_t *r, const char *suffix, const char *qname, uint8_t ip_out[4]) {
    char sfx[NVPN_MAX_NAME + 1], lab[64], full[128];
    size_t i, sl = 0;
    if (!r || !qname || !ip_out) return 0;
    if (suffix) {
        while (*suffix == '.' || *suffix == ' ') suffix++;
        sl = strlen(suffix);
        while (sl && (suffix[sl - 1] == '.' || suffix[sl - 1] == ' ')) sl--;
        if (sl > NVPN_MAX_NAME) return 0;
        memcpy(sfx, suffix, sl);
    }
    sfx[sl] = 0;
    for (i = 0; i < r->n_aliases; i++) {
        size_t n = nvpn_dns_normalize_label(r->aliases[i].alias, lab, sizeof lab);
        if (!n) continue;
        if (!eq_ci(lab, qname)) {
            if (!sl) continue;
            memcpy(full, lab, n); full[n] = '.';
            memcpy(full + n + 1, sfx, sl); full[n + 1 + sl] = 0;
            if (!eq_ci(full, qname)) continue;
        }
        {
            size_t m, total = (size_t)r->n_devices + r->n_admins;
            for (m = 0; m < total; m++) {
                const uint8_t *pk = m < r->n_devices ? r->devices[m] : r->admins[m - r->n_devices];
                if (!memcmp(pk, r->aliases[i].pubkey, 32)) { memcpy(ip_out, r->ips[m], 4); return 1; }
            }
        }
    }
    return 0;
}

int nvpn_dns_respond(const nvpn_roster_t *r, const char *suffix, int answer_name_errors,
                     const uint8_t *q, size_t qlen, uint8_t *resp, size_t cap) {
    uint16_t qd, i, answers = 0;
    size_t off = 12, o;
    int matched = 0;
    size_t qstart[4];
    if (!r || !q || !resp) return NVPN_ERR_ARG;
    if (qlen < 12 || (q[2] & 0x80)) return 0;       /* too short, or already a response */
    qd = (uint16_t)((q[4] << 8) | q[5]);
    if (qd == 0 || qd > 4) return 0;

    /* first pass: validate & copy questions to the response */
    if (cap < qlen) return NVPN_ERR_BUF;
    o = 12;
    for (i = 0; i < qd; i++) {
        size_t s = off;
        for (;;) {
            uint8_t l;
            if (off >= qlen) return 0;
            l = q[off++];
            if (l == 0) break;
            if (l & 0xC0) return 0;               /* compression in a question: not supported */
            if (off + l > qlen) return 0;
            off += l;
        }
        if (off + 4 > qlen) return 0;
        off += 4;
        qstart[i] = o;
        if (o + (off - s) > cap) return NVPN_ERR_BUF;
        memcpy(resp + o, q + s, off - s);
        o += off - s;
    }
    /* header */
    resp[0] = q[0]; resp[1] = q[1];
    resp[2] = (uint8_t)(0x80 | 0x04 | (q[2] & 0x01)); /* QR, AA, copy RD */
    resp[3] = 0;
    resp[4] = q[4]; resp[5] = q[5];
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;

    /* second pass: answers */
    off = 12;
    for (i = 0; i < qd; i++) {
        char name[256]; size_t nl = 0; uint16_t qtype; uint8_t ip[4];
        for (;;) {
            uint8_t l = q[off++];
            if (l == 0) break;
            if (nl + l + 1 >= sizeof name) return 0;
            if (nl) name[nl++] = '.';
            memcpy(name + nl, q + off, l); nl += l; off += l;
        }
        name[nl] = 0;
        qtype = (uint16_t)((q[off] << 8) | q[off + 1]);
        off += 4;
        if (nl == 0) continue;
        if (!nvpn_dns_lookup(r, suffix, name, ip)) continue;
        matched = 1;
        if (qtype != 1) continue;
        if (o + 16 > cap) return NVPN_ERR_BUF;
        resp[o++] = (uint8_t)(0xC0 | (qstart[i] >> 8)); resp[o++] = (uint8_t)qstart[i];
        resp[o++] = 0; resp[o++] = 1;                  /* TYPE A */
        resp[o++] = 0; resp[o++] = 1;                  /* CLASS IN */
        resp[o++] = 0; resp[o++] = 0; resp[o++] = 0; resp[o++] = DNS_TTL;
        resp[o++] = 0; resp[o++] = 4;
        memcpy(resp + o, ip, 4); o += 4;
        answers++;
    }
    if (!answers && !matched && !answer_name_errors) return 0;
    resp[3] = (uint8_t)((answers || matched) ? 0 : 3); /* NOERROR / NXDOMAIN */
    resp[6] = (uint8_t)(answers >> 8); resp[7] = (uint8_t)answers;
    return (int)o;
}
