/*
 * nvpn-esp32 — control-plane core of nostr-vpn, ported to portable C for ESP32.
 *
 * What this library implements (wire/semantics compatible with nostr-vpn 4.1.x):
 *   - Nostr identity: x-only secp256k1 keys, hex/npub (bech32) conversion
 *   - network_id normalisation and deterministic mesh IPv4 (10.44.x.y/32)
 *   - Signed roster events (kind 30388): NIP-01 id check + BIP-340 verify + parse
 *   - Roster update policy (admin-only, newer-only, freshness window)
 *   - Roster-gated source/destination admission by derived IP
 *   - MagicDNS name table + RFC1035 A-record responder (UDP/53 payload in/out)
 *
 * What it does NOT implement: the FIPS data plane (Noise sessions, discovery,
 * NAT traversal, FIPS-TCP). That lives in external crates that are not part of
 * the source tree this was extracted from. See README.md.
 *
 * No heap allocation is performed by this library. All sizes are fixed by the
 * NVPN_MAX_* macros below (override with -D at build time).
 */
#ifndef NVPN_H
#define NVPN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NVPN_MAX_MEMBERS
#define NVPN_MAX_MEMBERS 32 /* devices per roster */
#endif
#ifndef NVPN_MAX_ADMINS
#define NVPN_MAX_ADMINS 4
#endif
#ifndef NVPN_MAX_ALIASES
#define NVPN_MAX_ALIASES NVPN_MAX_MEMBERS
#endif
#ifndef NVPN_MAX_NETID
#define NVPN_MAX_NETID 63
#endif
#ifndef NVPN_MAX_NAME
#define NVPN_MAX_NAME 63
#endif
#ifndef NVPN_MAX_ALIAS
#define NVPN_MAX_ALIAS 63
#endif
/* Largest single decoded JSON string inside an event (tag value). */
#ifndef NVPN_MAX_STR
#define NVPN_MAX_STR 256
#endif

#define NVPN_PUBKEY_LEN 32
#define NVPN_JOIN_ROSTER_MAX_AGE_SECS (7u * 24u * 60u * 60u)
#define NVPN_JOIN_ROSTER_MAX_FUTURE_SECS (10u * 60u)
#define NVPN_SIGNED_ROSTER_KIND 30388

typedef enum {
    NVPN_OK = 0,
    NVPN_ERR_ARG = -1,
    NVPN_ERR_PARSE = -2,     /* malformed JSON / structure */
    NVPN_ERR_KIND = -3,      /* wrong event kind */
    NVPN_ERR_CONTENT = -4,   /* content must be empty */
    NVPN_ERR_ID = -5,        /* event id does not match contents */
    NVPN_ERR_SIG = -6,       /* signature invalid */
    NVPN_ERR_ROSTER = -7,    /* missing/invalid roster tags */
    NVPN_ERR_PUBKEY = -8,    /* invalid pubkey in tag */
    NVPN_ERR_CAPACITY = -9,  /* more members/admins/aliases than NVPN_MAX_* */
    NVPN_ERR_TOO_LONG = -10, /* string exceeds NVPN_MAX_STR */
    NVPN_ERR_POLICY = -11,   /* rejected by update policy */
    NVPN_ERR_STALE = -12,    /* older than / equal to current roster */
    NVPN_ERR_FRESH = -13,    /* outside freshness window */
    NVPN_ERR_BUF = -14       /* output buffer too small */
} nvpn_err_t;

/* ---------------------------------------------------------------- util --- */

/* out must hold 64 hex chars + NUL. */
void nvpn_hex_encode(const uint8_t *in, size_t len, char *out);
/* Accepts upper/lower case. Returns NVPN_OK or NVPN_ERR_ARG. */
int nvpn_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len);

void nvpn_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* ------------------------------------------------------------ identity --- */

/* Parse a Nostr public key given as 64-char hex or "npub1..." into 32 bytes. */
int nvpn_pubkey_parse(const char *s, uint8_t out[NVPN_PUBKEY_LEN]);
/* out needs >= 64 bytes ("npub1" + 52 data chars + 6 checksum = 63, + NUL). */
int nvpn_pubkey_to_npub(const uint8_t pk[NVPN_PUBKEY_LEN], char *out, size_t out_cap);

/* Generate/derive. secret must be 32 random bytes from a CSPRNG (esp_fill_random
 * is suitable once Wi-Fi/BT is on, otherwise use bootloader_random_enable()). */
int nvpn_pubkey_from_secret(const uint8_t secret[32], uint8_t pk_out[NVPN_PUBKEY_LEN]);
/* Optional side-channel hardening: blind the signing context with 32 random
 * bytes (call once at start-up with esp_fill_random()). */
int nvpn_secp_randomize(const uint8_t seed32[32]);
/* BIP-340 Schnorr sign a 32-byte message. aux32 may be NULL. */
int nvpn_schnorr_sign(const uint8_t secret[32], const uint8_t msg32[32],
                      const uint8_t *aux32, uint8_t sig_out[64]);
int nvpn_schnorr_verify(const uint8_t pk[NVPN_PUBKEY_LEN], const uint8_t msg32[32],
                        const uint8_t sig[64]);

/* ---------------------------------------------------- network id / IPs --- */

/* Same rules as nostr-vpn `normalize_runtime_network_id`: trims, strips legacy
 * "nostr-vpn:" prefix, hex-ish IDs lose whitespace/'-' and are lowercased.
 * Returns length (excluding NUL) or a negative nvpn_err_t. */
int nvpn_normalize_network_id(const char *in, char *out, size_t out_cap);

/* 10.44.(d[0]%254+1).(d[1]%254+1), d = SHA256(netid "\n" lowercase-hex(pubkey)).
 * ip_out is 4 bytes in network order. */
int nvpn_derive_tunnel_ip(const char *network_id, const uint8_t pk[NVPN_PUBKEY_LEN],
                          uint8_t ip_out[4]);

/* ------------------------------------------------------------- roster --- */

typedef struct {
    uint8_t pubkey[NVPN_PUBKEY_LEN];
    char alias[NVPN_MAX_ALIAS + 1];
} nvpn_alias_t;

typedef struct {
    char network_id[NVPN_MAX_NETID + 1]; /* as signed (not normalised) */
    char name[NVPN_MAX_NAME + 1];
    uint64_t signed_at;
    uint8_t signer[NVPN_PUBKEY_LEN];
    uint8_t event_id[32];
    uint16_t n_devices, n_admins, n_aliases;
    uint8_t devices[NVPN_MAX_MEMBERS][NVPN_PUBKEY_LEN]; /* sorted, unique */
    uint8_t admins[NVPN_MAX_ADMINS][NVPN_PUBKEY_LEN];   /* sorted, unique */
    nvpn_alias_t aliases[NVPN_MAX_ALIASES];
    /* Derived mesh IPv4 per member (devices first, then admins); filled by
     * nvpn_roster_verify so per-packet lookups never hash. */
    uint8_t ips[NVPN_MAX_MEMBERS + NVPN_MAX_ADMINS][4];
} nvpn_roster_t;

/* Verify (kind, empty content, event id, BIP-340 signature, roster tags) and
 * parse a signed roster event given as the JSON text of the Nostr event
 * (the `event` field of nostr-vpn's SignedRoster; NOT the wrapper object).
 * `json` need not be NUL-terminated. Uses ~2 KiB of stack (measured, -O2, x86-64). */
int nvpn_roster_verify(const char *json, size_t len, nvpn_roster_t *out);

/* Membership helpers (devices and admins both count as members). */
int nvpn_roster_is_member(const nvpn_roster_t *r, const uint8_t pk[NVPN_PUBKEY_LEN]);
int nvpn_roster_is_admin(const nvpn_roster_t *r, const uint8_t pk[NVPN_PUBKEY_LEN]);

/* Freshness window used by nostr-vpn for join delivery: not older than 7 days
 * and not more than 10 minutes in the future. Needs a valid wall clock (SNTP). */
int nvpn_roster_check_fresh(const nvpn_roster_t *r, uint64_t now_unix);

/* Update policy for an already-trusted roster: same network id, signed by a
 * CURRENT admin, strictly newer. On NVPN_OK, *current is replaced.
 * The initial roster must be trusted through provisioning (see
 * nvpn_roster_bootstrap). */
int nvpn_roster_update(nvpn_roster_t *current, const nvpn_roster_t *incoming);

/* Accept a first roster only if signed by `trusted_admin`. */
int nvpn_roster_bootstrap(nvpn_roster_t *current, const nvpn_roster_t *incoming,
                          const uint8_t trusted_admin[NVPN_PUBKEY_LEN]);

/* ------------------------------------------------ routing / admission --- */

/* Map a mesh IPv4 (network order) back to a roster member. Returns index into
 * devices (0..n_devices-1), or n_devices+i for admins, or -1 when unknown. */
int nvpn_roster_lookup_ip(const nvpn_roster_t *r, const uint8_t ip[4], uint8_t pk_out[NVPN_PUBKEY_LEN]);

/* Inbound admission: authenticated peer `peer` may only deliver packets whose
 * IPv4 source is its own derived address and whose destination is `self_ip`.
 * pkt/len is a raw IPv4 packet. Returns 1 to accept, 0 to drop. */
int nvpn_admit_inbound(const nvpn_roster_t *r, const uint8_t peer[NVPN_PUBKEY_LEN],
                       const uint8_t self_ip[4], const uint8_t *pkt, size_t len);

/* Outbound: pick the peer for an IPv4 packet destination inside 10.44.0.0/16.
 * Returns 1 and fills peer_out on success, 0 if destination is not a member. */
int nvpn_route_outbound(const nvpn_roster_t *r, const uint8_t *pkt, size_t len,
                        uint8_t peer_out[NVPN_PUBKEY_LEN]);

/* ----------------------------------------------------------- MagicDNS --- */

/* Same label rules as nostr-vpn `normalize_magic_dns_label`: ASCII alnum
 * lowercased, runs of anything else collapse to '-', trimmed, max 63.
 * Returns length, or 0 when nothing usable remains. out_cap >= 64. */
size_t nvpn_dns_normalize_label(const char *in, char *out, size_t out_cap);

/* Resolve `qname` (no trailing dot, any case) against the roster aliases.
 * Both "<alias>" and "<alias>.<suffix>" match. Returns 1 and sets ip_out. */
int nvpn_dns_lookup(const nvpn_roster_t *r, const char *suffix, const char *qname,
                    uint8_t ip_out[4]);

/* Build a MagicDNS response for a DNS query datagram. Behaviour mirrors
 * nostr-vpn: A queries for known names get an answer (TTL 30); other types for
 * a known name get NOERROR/empty; unknown names get NXDOMAIN when
 * `answer_name_errors` is non-zero, else the query is "not handled".
 * Returns response length (>0), 0 if not handled, <0 on error. */
int nvpn_dns_respond(const nvpn_roster_t *r, const char *suffix, int answer_name_errors,
                     const uint8_t *query, size_t qlen, uint8_t *resp, size_t resp_cap);

#ifdef __cplusplus
}
#endif
#endif /* NVPN_H */
