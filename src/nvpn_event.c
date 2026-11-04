/* Signed roster (Nostr kind 30388) verification and parsing.
 *
 * The event is validated without allocating: the JSON object is scanned once to
 * record the spans of its fields, then the NIP-01 serialisation
 *   [0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"]
 * is streamed straight into SHA-256 while the tags are decoded, which both
 * yields the event id and extracts the roster in a single pass.
 * Escaping matches serde_json (what the Rust nostr crate hashes). */
#include "nvpn_internal.h"

typedef struct { const char *p, *end; } cur_t;
typedef struct { const char *b, *e; int present; } span_t;

static void ws(cur_t *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

/* ------------------------------------------------------------ sinks --- */

typedef struct {
    nvpn_sha256_ctx *sha; /* may be NULL */
    char *buf;            /* may be NULL */
    size_t cap, len;
    int ovf;
} sink_t;

static void sha_put(sink_t *s, const char *d, size_t n) {
    if (s->sha) nvpn_sha256_update(s->sha, (const uint8_t *)d, n);
}

static void sink_byte(sink_t *s, uint8_t b) {
    static const char hx[] = "0123456789abcdef";
    if (s->sha) {
        if (b == '"') sha_put(s, "\\\"", 2);
        else if (b == '\\') sha_put(s, "\\\\", 2);
        else if (b == 8) sha_put(s, "\\b", 2);
        else if (b == 9) sha_put(s, "\\t", 2);
        else if (b == 10) sha_put(s, "\\n", 2);
        else if (b == 12) sha_put(s, "\\f", 2);
        else if (b == 13) sha_put(s, "\\r", 2);
        else if (b < 0x20) { char u[6] = {'\\', 'u', '0', '0', hx[b >> 4], hx[b & 15]}; sha_put(s, u, 6); }
        else sha_put(s, (const char *)&b, 1);
    }
    if (s->buf) {
        if (s->len < s->cap) s->buf[s->len++] = (char)b; else s->ovf = 1;
    }
}

size_t nvpn_utf8_encode(uint32_t cp, uint8_t *o) {
    if (cp < 0x80) { o[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800) { o[0] = (uint8_t)(0xC0 | (cp >> 6)); o[1] = (uint8_t)(0x80 | (cp & 63)); return 2; }
    if (cp < 0x10000) {
        o[0] = (uint8_t)(0xE0 | (cp >> 12)); o[1] = (uint8_t)(0x80 | ((cp >> 6) & 63));
        o[2] = (uint8_t)(0x80 | (cp & 63)); return 3;
    }
    o[0] = (uint8_t)(0xF0 | (cp >> 18)); o[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
    o[2] = (uint8_t)(0x80 | ((cp >> 6) & 63)); o[3] = (uint8_t)(0x80 | (cp & 63)); return 4;
}

static int hex4(const char *p, uint32_t *v) {
    int i; uint32_t r = 0;
    for (i = 0; i < 4; i++) {
        char c = p[i]; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        r = (r << 4) | (uint32_t)d;
    }
    *v = r; return 1;
}

/* Decode a JSON string at c (positioned at the opening quote) into the sink. */
static int dec_string(cur_t *c, sink_t *s) {
    if (c->p >= c->end || *c->p != '"') return NVPN_ERR_PARSE;
    c->p++;
    for (;;) {
        uint8_t ch;
        if (c->p >= c->end) return NVPN_ERR_PARSE;
        ch = (uint8_t)*c->p++;
        if (ch == '"') return NVPN_OK;
        if (ch < 0x20) return NVPN_ERR_PARSE;
        if (ch != '\\') { sink_byte(s, ch); continue; }
        if (c->p >= c->end) return NVPN_ERR_PARSE;
        ch = (uint8_t)*c->p++;
        switch (ch) {
        case '"': case '\\': case '/': sink_byte(s, ch); break;
        case 'b': sink_byte(s, 8); break;
        case 'f': sink_byte(s, 12); break;
        case 'n': sink_byte(s, 10); break;
        case 'r': sink_byte(s, 13); break;
        case 't': sink_byte(s, 9); break;
        case 'u': {
            uint32_t cp, lo; uint8_t u8[4]; size_t n, i;
            if (c->end - c->p < 4 || !hex4(c->p, &cp)) return NVPN_ERR_PARSE;
            c->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (c->end - c->p < 6 || c->p[0] != '\\' || c->p[1] != 'u' || !hex4(c->p + 2, &lo) ||
                    lo < 0xDC00 || lo > 0xDFFF) return NVPN_ERR_PARSE;
                c->p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return NVPN_ERR_PARSE;
            }
            n = nvpn_utf8_encode(cp, u8);
            for (i = 0; i < n; i++) sink_byte(s, u8[i]);
            break;
        }
        default: return NVPN_ERR_PARSE;
        }
    }
}

/* Skip any JSON value; records nothing. depth-limited. */
static int skip_value(cur_t *c, int depth) {
    if (depth > 16) return NVPN_ERR_PARSE;
    ws(c);
    if (c->p >= c->end) return NVPN_ERR_PARSE;
    if (*c->p == '"') { sink_t s = {0}; return dec_string(c, &s); }
    if (*c->p == '{' || *c->p == '[') {
        char close = *c->p == '{' ? '}' : ']';
        int obj = *c->p == '{';
        c->p++; ws(c);
        if (c->p < c->end && *c->p == close) { c->p++; return NVPN_OK; }
        for (;;) {
            int r;
            ws(c);
            if (obj) {
                sink_t s = {0};
                if ((r = dec_string(c, &s))) return r;
                ws(c);
                if (c->p >= c->end || *c->p++ != ':') return NVPN_ERR_PARSE;
            }
            if ((r = skip_value(c, depth + 1))) return r;
            ws(c);
            if (c->p >= c->end) return NVPN_ERR_PARSE;
            if (*c->p == ',') { c->p++; continue; }
            if (*c->p == close) { c->p++; return NVPN_OK; }
            return NVPN_ERR_PARSE;
        }
    }
    /* number / true / false / null */
    {
        const char *st = c->p;
        while (c->p < c->end && (*c->p == '-' || *c->p == '+' || *c->p == '.' || (*c->p >= '0' && *c->p <= '9') ||
                                 (*c->p >= 'a' && *c->p <= 'z') || (*c->p >= 'A' && *c->p <= 'Z'))) c->p++;
        return c->p == st ? NVPN_ERR_PARSE : NVPN_OK;
    }
}

static int parse_u64(span_t sp, uint64_t *out) {
    const char *p = sp.b; uint64_t v = 0;
    if (!sp.present || p >= sp.e) return NVPN_ERR_PARSE;
    for (; p < sp.e; p++) {
        unsigned d;
        if (*p < '0' || *p > '9') return NVPN_ERR_PARSE;
        d = (unsigned)(*p - '0');
        if (v > (UINT64_MAX - d) / 10) return NVPN_ERR_PARSE;
        v = v * 10 + d;
    }
    *out = v; return NVPN_OK;
}

static int span_hex(span_t sp, uint8_t *out, size_t n) {
    cur_t c; char tmp[130]; sink_t s = {0};
    int r;
    if (!sp.present) return NVPN_ERR_PARSE;
    c.p = sp.b; c.end = sp.e;
    s.buf = tmp; s.cap = sizeof tmp - 1;
    if ((r = dec_string(&c, &s))) return r;
    if (s.ovf || s.len != n * 2) return NVPN_ERR_PARSE;
    return nvpn_hex_decode(tmp, s.len, out, n) == NVPN_OK ? NVPN_OK : NVPN_ERR_PARSE;
}

/* -------------------------------------------------------- roster build --- */

static int cmp32(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 32); }

/* Insert into a sorted, de-duplicated array of 32-byte keys. */
static int sorted_insert(uint8_t (*arr)[32], uint16_t *n, size_t cap, const uint8_t pk[32]) {
    size_t i = 0;
    while (i < *n && cmp32(arr[i], pk) < 0) i++;
    if (i < *n && cmp32(arr[i], pk) == 0) return NVPN_OK;
    if (*n >= cap) return NVPN_ERR_CAPACITY;
    memmove(arr[i + 1], arr[i], (size_t)(*n - i) * 32);
    memcpy(arr[i], pk, 32);
    (*n)++;
    return NVPN_OK;
}

static void trim_ascii(const char **b, size_t *n) {
    while (*n && (**b == ' ' || **b == '\t' || **b == '\n' || **b == '\r')) { (*b)++; (*n)--; }
    while (*n && ((*b)[*n - 1] == ' ' || (*b)[*n - 1] == '\t' || (*b)[*n - 1] == '\n' || (*b)[*n - 1] == '\r')) (*n)--;
}

typedef struct {
    nvpn_roster_t *r;
    int app_ok, ver_ok, have_id;
} build_t;

static int tag_pubkey(const char *s, size_t n, uint8_t out[32]) {
    char t[NVPN_MAX_STR + 1];
    trim_ascii(&s, &n);
    if (n >= sizeof t) return NVPN_ERR_PUBKEY;
    memcpy(t, s, n); t[n] = 0;
    return nvpn_pubkey_parse(t, out) == NVPN_OK ? NVPN_OK : NVPN_ERR_PUBKEY;
}

static int apply_tag(build_t *bt, char (*v)[NVPN_MAX_STR + 1], size_t *vl, int *ovf, int count) {
    nvpn_roster_t *r = bt->r;
    const char *s1 = v[1], *s2 = v[2];
    size_t n1 = vl[1], n2 = vl[2];
    const char *k = v[0];
    uint8_t pk[32];
    int rc;
    if (count == 0) return NVPN_OK;
    if (count > 1) { trim_ascii(&s1, &n1); }

    if (vl[0] == 1 && k[0] == 'd') {
        if (count < 2) { bt->have_id = 0; r->network_id[0] = 0; return NVPN_OK; }
        if (ovf[1] || n1 > NVPN_MAX_NETID) return NVPN_ERR_TOO_LONG;
        memcpy(r->network_id, s1, n1); r->network_id[n1] = 0;
        bt->have_id = n1 > 0;
    } else if (vl[0] == 3 && !memcmp(k, "app", 3)) {
        if (count > 1 && !ovf[1] && vl[1] == 23 && !memcmp(v[1], "nostr-vpn/shared-roster", 23)) bt->app_ok = 1;
    } else if (vl[0] == 1 && k[0] == 'v') {
        if (count > 1 && !ovf[1] && vl[1] == 1 && v[1][0] == '1') bt->ver_ok = 1;
    } else if (vl[0] == 4 && !memcmp(k, "name", 4)) {
        if (count > 1) {
            size_t m = n1 > NVPN_MAX_NAME ? NVPN_MAX_NAME : n1;
            memcpy(r->name, s1, m); r->name[m] = 0;
        }
    } else if ((vl[0] == 6 && !memcmp(k, "member", 6)) || (vl[0] == 5 && !memcmp(k, "admin", 5))) {
        if (count > 1) {
            int is_admin = (vl[0] == 5);
            if (ovf[1] || (rc = tag_pubkey(s1, n1, pk)) != NVPN_OK) return NVPN_ERR_PUBKEY;
            rc = is_admin ? sorted_insert(r->admins, &r->n_admins, NVPN_MAX_ADMINS, pk)
                          : sorted_insert(r->devices, &r->n_devices, NVPN_MAX_MEMBERS, pk);
            if (rc) return rc;
        }
    } else if (vl[0] == 5 && !memcmp(k, "alias", 5)) {
        if (count > 2) {
            size_t i, m;
            trim_ascii(&s2, &n2);
            n1 = vl[1]; s1 = v[1]; trim_ascii(&s1, &n1);
            if (ovf[1] || tag_pubkey(s1, n1, pk) != NVPN_OK) return NVPN_ERR_PUBKEY;
            if (n2 == 0) return NVPN_OK;
            for (i = 0; i < r->n_aliases; i++) if (!cmp32(r->aliases[i].pubkey, pk)) break;
            if (i == r->n_aliases) {
                if (r->n_aliases >= NVPN_MAX_ALIASES) return NVPN_ERR_CAPACITY;
                r->n_aliases++;
            }
            m = n2 > NVPN_MAX_ALIAS ? NVPN_MAX_ALIAS : n2;
            memcpy(r->aliases[i].pubkey, pk, 32);
            memcpy(r->aliases[i].alias, s2, m); r->aliases[i].alias[m] = 0;
        }
    }
    return NVPN_OK;
}

/* Stream tags array into the hash (if sha != NULL) and build the roster. */
static int stream_tags(span_t tags, nvpn_sha256_ctx *sha, build_t *bt) {
    cur_t c; int r, first_tag = 1;
    if (!tags.present) return NVPN_ERR_PARSE;
    c.p = tags.b; c.end = tags.e;
    ws(&c);
    if (c.p >= c.end || *c.p++ != '[') return NVPN_ERR_PARSE;
    nvpn_sha256_update(sha, (const uint8_t *)"[", 1);
    ws(&c);
    if (c.p < c.end && *c.p == ']') { c.p++; goto done; }
    for (;;) {
        char v[3][NVPN_MAX_STR + 1]; size_t vl[3] = {0, 0, 0}; int ovf[3] = {0, 0, 0};
        int count = 0, first_el = 1;
        ws(&c);
        if (!first_tag) nvpn_sha256_update(sha, (const uint8_t *)",", 1);
        first_tag = 0;
        if (c.p >= c.end || *c.p++ != '[') return NVPN_ERR_PARSE;
        nvpn_sha256_update(sha, (const uint8_t *)"[", 1);
        ws(&c);
        if (c.p < c.end && *c.p == ']') { c.p++; }
        else for (;;) {
            sink_t s = {0};
            ws(&c);
            if (!first_el) nvpn_sha256_update(sha, (const uint8_t *)",", 1);
            first_el = 0;
            nvpn_sha256_update(sha, (const uint8_t *)"\"", 1);
            s.sha = sha;
            if (count < 3) { s.buf = v[count]; s.cap = NVPN_MAX_STR; }
            if ((r = dec_string(&c, &s))) return r;
            nvpn_sha256_update(sha, (const uint8_t *)"\"", 1);
            if (count < 3) { v[count][s.len] = 0; vl[count] = s.len; ovf[count] = s.ovf; }
            count++;
            ws(&c);
            if (c.p >= c.end) return NVPN_ERR_PARSE;
            if (*c.p == ',') { c.p++; continue; }
            if (*c.p == ']') { c.p++; break; }
            return NVPN_ERR_PARSE;
        }
        nvpn_sha256_update(sha, (const uint8_t *)"]", 1);
        if ((r = apply_tag(bt, v, vl, ovf, count > 3 ? 3 : count))) return r;
        ws(&c);
        if (c.p >= c.end) return NVPN_ERR_PARSE;
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == ']') { c.p++; break; }
        return NVPN_ERR_PARSE;
    }
done:
    nvpn_sha256_update(sha, (const uint8_t *)"]", 1);
    ws(&c);
    return c.p == c.end ? NVPN_OK : NVPN_ERR_PARSE;
}

/* Locate the fields of a Nostr event object. */
typedef struct { span_t id, pubkey, created_at, kind, tags, content, sig, event; } fields_t;

static int scan_object(const char *json, size_t len, fields_t *f) {
    cur_t c; int r;
    c.p = json; c.end = json + len;
    memset(f, 0, sizeof *f);
    ws(&c);
    if (c.p >= c.end || *c.p++ != '{') return NVPN_ERR_PARSE;
    ws(&c);
    if (c.p < c.end && *c.p == '}') { c.p++; goto tail; }
    for (;;) {
        char key[16]; sink_t ks = {0}; span_t *dst = NULL; const char *vb;
        ws(&c);
        ks.buf = key; ks.cap = sizeof key - 1;
        if ((r = dec_string(&c, &ks))) return r;
        key[ks.len] = 0;
        ws(&c);
        if (c.p >= c.end || *c.p++ != ':') return NVPN_ERR_PARSE;
        ws(&c);
        vb = c.p;
        if (!ks.ovf) {
            if (!strcmp(key, "id")) dst = &f->id;
            else if (!strcmp(key, "pubkey")) dst = &f->pubkey;
            else if (!strcmp(key, "created_at")) dst = &f->created_at;
            else if (!strcmp(key, "kind")) dst = &f->kind;
            else if (!strcmp(key, "tags")) dst = &f->tags;
            else if (!strcmp(key, "content")) dst = &f->content;
            else if (!strcmp(key, "sig")) dst = &f->sig;
            else if (!strcmp(key, "event")) dst = &f->event;
        }
        if ((r = skip_value(&c, 0))) return r;
        if (dst) {
            if (dst->present) return NVPN_ERR_PARSE; /* duplicate key */
            dst->b = vb; dst->e = c.p; dst->present = 1;
        }
        ws(&c);
        if (c.p >= c.end) return NVPN_ERR_PARSE;
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == '}') { c.p++; break; }
        return NVPN_ERR_PARSE;
    }
tail:
    ws(&c);
    return c.p == c.end ? NVPN_OK : NVPN_ERR_PARSE;
}

int nvpn_roster_verify(const char *json, size_t len, nvpn_roster_t *out) {
    fields_t f; nvpn_sha256_ctx sha; build_t bt;
    uint8_t pk[32], idb[32], sig[64], digest[32];
    uint64_t created, kind;
    char num[24]; int r, i;
    cur_t cc; sink_t cs = {0}; char cb[2];

    if (!json || !out) return NVPN_ERR_ARG;
    if ((r = scan_object(json, len, &f))) return r;
    if (f.event.present && !f.sig.present) { /* SignedRoster { event } wrapper */
        json = f.event.b; len = (size_t)(f.event.e - f.event.b);
        if ((r = scan_object(json, len, &f))) return r;
    }
    if (!f.id.present || !f.pubkey.present || !f.created_at.present || !f.kind.present ||
        !f.tags.present || !f.content.present || !f.sig.present) return NVPN_ERR_PARSE;

    if ((r = parse_u64(f.kind, &kind))) return r;
    if (kind != NVPN_SIGNED_ROSTER_KIND) return NVPN_ERR_KIND;
    /* content must be exactly "" */
    cc.p = f.content.b; cc.end = f.content.e; cs.buf = cb; cs.cap = 1;
    if (*cc.p != '"') return NVPN_ERR_PARSE;
    if ((r = dec_string(&cc, &cs))) return r;
    if (cs.len != 0 || cs.ovf) return NVPN_ERR_CONTENT;
    if ((r = parse_u64(f.created_at, &created))) return r;
    if ((r = span_hex(f.pubkey, pk, 32)) || (r = span_hex(f.id, idb, 32)) || (r = span_hex(f.sig, sig, 64))) return r;

    memset(out, 0, sizeof *out);
    memset(&bt, 0, sizeof bt);
    bt.r = out;

    nvpn_sha256_init(&sha);
    nvpn_sha256_update(&sha, (const uint8_t *)"[0,\"", 4);
    {
        char hex[65];
        nvpn_hex_encode(pk, 32, hex);
        nvpn_sha256_update(&sha, (const uint8_t *)hex, 64);
    }
    nvpn_sha256_update(&sha, (const uint8_t *)"\",", 2);
    i = 0; { uint64_t v = created; char t[24]; int n = 0; do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v); while (n) num[i++] = t[--n]; }
    nvpn_sha256_update(&sha, (const uint8_t *)num, (size_t)i);
    nvpn_sha256_update(&sha, (const uint8_t *)",", 1);
    i = 0; { uint64_t v = kind; char t[24]; int n = 0; do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v); while (n) num[i++] = t[--n]; }
    nvpn_sha256_update(&sha, (const uint8_t *)num, (size_t)i);
    nvpn_sha256_update(&sha, (const uint8_t *)",", 1);
    if ((r = stream_tags(f.tags, &sha, &bt))) return r;
    nvpn_sha256_update(&sha, (const uint8_t *)",\"\"]", 4);
    nvpn_sha256_final(&sha, digest);

    if (memcmp(digest, idb, 32) != 0) return NVPN_ERR_ID;
    if ((r = nvpn_schnorr_verify(pk, digest, sig)) != NVPN_OK) return r == NVPN_ERR_PUBKEY ? r : NVPN_ERR_SIG;

    if (!bt.app_ok || !bt.ver_ok || !bt.have_id) return NVPN_ERR_ROSTER;
    out->signed_at = created;
    memcpy(out->signer, pk, 32);
    memcpy(out->event_id, digest, 32);
    for (i = 0; i < out->n_devices + out->n_admins; i++) {
        const uint8_t *m = i < out->n_devices ? out->devices[i] : out->admins[i - out->n_devices];
        if (nvpn_derive_tunnel_ip(out->network_id, m, out->ips[i]) != NVPN_OK) return NVPN_ERR_ROSTER;
    }
    return NVPN_OK;
}
