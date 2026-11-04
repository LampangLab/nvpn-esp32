/*
 * fips — a minimal FIPS (Free Internetworking Peering System) leaf node in C for ESP32.
 *
 * Sans-IO: the library never touches sockets, clocks or RNGs. The application
 * supplies a send callback (one UDP datagram to the upstream peer), a CSPRNG and
 * a millisecond clock, and feeds received datagrams into fips_input().
 *
 * Implemented (wire-compatible with FIPS FMP v1 / FSP v0, see docs/reference/wire-formats.md):
 *   - FMP link layer as Noise IK *initiator* over UDP to ONE upstream peer (a direct peer or a public seed)
 *   - established-frame AEAD, replay window, heartbeat, disconnect, liveness timeout, auto-reconnect
 *   - mesh participation as a leaf: TreeAnnounce (parent = upstream), FilterAnnounce (bloom with our address),
 *     LookupRequest/LookupResponse (find and verify a destination's coordinates, answer lookups for us),
 *     coordinate cache, CoordsWarmup / CP-flag piggyback, CoordsRequired / PathBroken recovery
 *   - FSP end-to-end sessions (Noise XK, initiator and responder) over multiple hops through the upstream,
 *     port-multiplexed datagrams, EndpointData packets, automatic re-open when the peer lost the session
 *
 * Not implemented: forwarding for other nodes (we are never a transit node or parent), link/session rekey
 * (the peer's rekey msg1 is ignored; its attempts fail harmlessly), MMP reports, other transports,
 * direct NAT hole punching (traffic keeps flowing through the upstream).
 */
#ifndef FIPS_H
#define FIPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIPS_MTU 1500
#define FIPS_NODE_ADDR_LEN 16
#ifndef FIPS_MAX_SESSIONS
#define FIPS_MAX_SESSIONS 8   /* idle sessions are evicted LRU when full */
#endif
#ifndef FIPS_COORD_CACHE
#define FIPS_COORD_CACHE 8    /* destination tree coordinates (LRU) */
#endif
#ifndef FIPS_MAX_LOOKUPS
#define FIPS_MAX_LOOKUPS 4    /* concurrent coordinate lookups */
#endif
/* diagnostic counter indexes */
enum { FIPS_DG_TO_US, FIPS_DG_OTHER, FIPS_DG_SETUP_RX, FIPS_DG_SETUP_REJ, FIPS_DG_ACK_RX, FIPS_DG_MSG3_RX,
       FIPS_DG_EST_RX, FIPS_DG_EST_NOSESS, FIPS_DG_EST_BAD, FIPS_DG_EST_AEAD, FIPS_DG_EST_OK, FIPS_DG_ERRSIG,
       FIPS_DG_DEAD_RESET, FIPS_DG_LAST_ERR, FIPS_DG_LAST_PT4, FIPS_DG_PKT_DELIVERED, FIPS_DG_PROMOTE, FIPS_DG_RR_TX, FIPS_DG_N };
/* rekey/role trace: a small ring of timestamped events (no keys, no payloads) for interop reports */
#ifndef FIPS_TRACE_N
#define FIPS_TRACE_N 32
#endif
enum { FIPS_TR_LINK_UP = 1, FIPS_TR_LINK_DOWN, FIPS_TR_FMP_MSG1_RX, FIPS_TR_FMP_KFLIP, FIPS_TR_FSP_SETUP_RX,
       FIPS_TR_FSP_MSG3_NEW, FIPS_TR_FSP_MSG3_REKEY, FIPS_TR_FSP_PROMOTE, FIPS_TR_FSP_DEAD_RESET,
       FIPS_TR_ROLE_SUPPORT_TX, FIPS_TR_ROLE_SUPPORT_RX, FIPS_TR_ROLE_CLIENT_TX, FIPS_TR_ROLE_CLIENT_RX,
       FIPS_TR_ROLE_TREE_TX, FIPS_TR_ROLE_FALLBACK, FIPS_TR_ROLE_UNSUPPORTED };
typedef struct { uint32_t t_ms, tx, rx; uint8_t kind, arg; } fips_trace_t;
#define FIPS_MAX_DEPTH 16     /* longest tree path (entries incl. self) we handle */

typedef enum {
    FIPS_OK = 0,
    FIPS_ERR_ARG = -1,
    FIPS_ERR_STATE = -2,    /* not connected / wrong state */
    FIPS_ERR_CRYPTO = -3,
    FIPS_ERR_PARSE = -4,
    FIPS_ERR_AUTH = -5,     /* AEAD failure */
    FIPS_ERR_REPLAY = -6,
    FIPS_ERR_NOSPACE = -7,
    FIPS_ERR_TOOBIG = -8
} fips_err_t;

typedef enum {
    FIPS_LINK_DOWN = 0,
    FIPS_LINK_HANDSHAKING = 1,
    FIPS_LINK_UP = 2
} fips_link_state_t;

typedef struct {
    /* Transmit one datagram to the upstream peer's UDP endpoint. */
    void (*send)(void *ud, const uint8_t *pkt, size_t len);
    /* Fill buf with n cryptographically secure random bytes. */
    void (*random)(void *ud, uint8_t *buf, size_t n);
    /* Application data from a remote node (after FSP decryption). May be NULL. */
    void (*on_data)(void *ud, const uint8_t src_node_addr[FIPS_NODE_ADDR_LEN],
                    uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t len);
    void *ud;
    /* Inbound sessions: return non-zero to accept the remote static key (x-only). NULL = reject
     * all inbound sessions (we can still initiate). */
    int (*accept_peer)(void *ud, const uint8_t peer_xonly[32]);
    /* Raw packet payload (FSP EndpointData, msg type 0x15: what nostr-vpn uses for IP packets)
     * from an authenticated peer. May be NULL. */
    void (*on_packet)(void *ud, const uint8_t peer_xonly[32], const uint8_t *pkt, size_t len);
} fips_io_t;

/* ---- internal state (exposed so callers can allocate it statically; treat as opaque) ---- */

typedef struct { uint64_t highest; uint64_t bits[32]; } fips_replay_t;

typedef struct {
    uint8_t ck[32], h[32], k[32];
    uint64_t n;
    int has_key;
} fips_noise_t;

typedef struct {
    int state;                     /* fips_link_state_t */
    uint32_t our_idx, their_idx;
    uint8_t e_secret[32];          /* handshake ephemeral (valid while HANDSHAKING) */
    fips_noise_t hs;
    uint8_t msg1[114];             /* kept for resends */
    uint8_t send_key[32], recv_key[32];
    uint64_t send_ctr;
    fips_replay_t replay;
    uint64_t t_start_ms, t_last_rx_ms, t_last_tx_ms, t_msg1_ms, t_hs_start_ms;
    uint32_t resends;
    uint8_t peer_epoch[8];
    int want_up;                   /* auto-reconnect after fips_connect() */
    uint64_t t_down_ms;
} fips_link_t;

typedef struct {
    int state;                     /* 0 free, 1 awaiting ack, 2 established, 3 awaiting msg3 (responder), 4 awaiting coordinates */
    uint8_t warm_left;             /* data packets that still piggyback coordinates (CP flag) */
    uint64_t t_warm_ms;            /* last standalone CoordsWarmup (rate limit) */
    uint32_t unanswered;           /* application messages sent since we last heard anything from the peer */
    uint64_t t_unanswered_ms;      /* when the first of those was sent */
    uint8_t peer_xonly[32];
    uint8_t peer_addr[16];
    fips_noise_t hs;
    uint8_t e_secret[32];
    uint8_t send_key[32], recv_key[32];
    uint64_t send_ctr, t_start_ms, t_setup_ms;
    fips_replay_t replay;
    uint8_t setup_pkt[512];        /* SessionSetup (initiator) / SessionAck (responder) payload, for resend */
    uint8_t responder;             /* 1 if the remote side initiated */
    uint64_t t_used_ms;            /* last rx/tx, for LRU eviction */
    size_t setup_len;
    uint32_t resends;
    /* FSP rekey (K-bit epochs): the key set in use is selected by the K flag of each frame */
    uint8_t k, k_known;            /* K bit we send with / whether it is known (a fresh responder session learns it from the peer) */
    uint8_t pend;                  /* a rekeyed key set waits for the peer's first authenticated frame with the other K bit */
    uint8_t pend_send[32], pend_recv[32]; fips_replay_t pend_replay;
    /* MMP session ReceiverReport (0x12): delivery feedback the peer's recovery logic waits for */
    uint64_t rx_pkts, rx_bytes, rx_hi, rr_last_pkts, rr_last_bytes, t_rr_ms, t_rx_ms; uint32_t rx_echo_ts; uint8_t rr_pending;
    uint8_t prev, prev_k, prev_recv[32]; fips_replay_t prev_replay; uint64_t t_prev_ms;   /* previous epoch, drained for FSP_DRAIN_MS */
} fips_session_t;

/* cached tree coordinates of a destination: c[0] = the node itself ... c[n-1] = root */
typedef struct {
    uint8_t used, verified, n;
    uint8_t addr[16];
    uint8_t c[FIPS_MAX_DEPTH][16];
    uint64_t t_ms;
} fips_coord_t;

typedef struct {
    uint8_t active, attempt;
    uint8_t target_xonly[32], target_addr[16];
    uint8_t ids[4][8];
    uint64_t t_sent_ms, t_start_ms;
} fips_lookup_t;

typedef struct {
    fips_io_t io;
    uint8_t secret[32];
    uint8_t pub_xonly[32];
    uint8_t pub_comp[33];          /* compressed, true parity */
    uint8_t node_addr[16];
    uint8_t epoch[8];
    uint8_t upstream_xonly[32];
    uint8_t upstream_addr[16];
    fips_link_t link;
    fips_session_t sess[FIPS_MAX_SESSIONS];
    uint8_t up_anc[FIPS_MAX_DEPTH][16];  /* upstream's ancestry (upstream -> root) from its TreeAnnounce */
    uint8_t up_anc_raw[FIPS_MAX_DEPTH][32]; /* the same, as wire entries (addr, seq, timestamp) */
    uint8_t up_anc_n;
    uint64_t up_ts, t_up_ts_ms;    /* upstream's declaration timestamp (unix s) and when we received it */
    /* mesh participation (leaf that hangs off its upstream, see fips_mesh.c) */
    uint64_t tree_seq, filter_seq;
    uint64_t t_announce_ms;        /* next (re)announcement of tree + filter */
    uint8_t announce_n;            /* announcements sent since the ancestry last changed */
    uint8_t announce_due;
    fips_coord_t cc[FIPS_COORD_CACHE];
    fips_lookup_t lk[FIPS_MAX_LOOKUPS];
    /* diagnostics (see FIPS_DG_*): cheap event counters, readable via nvpn_tunnel_stats */
    uint32_t diag[FIPS_DG_N];
    fips_trace_t trace[FIPS_TRACE_N]; uint32_t trace_n;   /* total events ever recorded; slot = index % FIPS_TRACE_N */
    uint32_t n_tx, n_rx;           /* link frames sent / authenticated frames received (for trace context) */
    /* client-only role negotiation (see fips_mesh.c) */
    uint8_t allow_router_fallback; /* default 0: if the upstream has no client-only support, stay silent (role 3) instead of advertising as a router; 1 = legacy TreeAnnounce fallback (tests only) */
    uint8_t client_role_off;       /* set to 1 before fips_connect() to skip the client-only negotiation (always TreeAnnounce); 2 = test hook, ignore the upstream's answer */
    uint8_t role;                  /* 0 negotiating, 1 client-only active, 2 TreeAnnounce (router fallback, opt-in), 3 waiting: upstream has no leaf support, nothing advertised */
    uint8_t peer_client_support;   /* upstream sent ClientSupport (0x53) or ClientOnly */
    uint8_t support_sent;
    uint64_t client_seq;           /* ClientOnly declaration sequence */
    uint64_t t_role_start_ms;
    uint64_t unix_hi;              /* highest unix time handed out by fips_unix_now */
    uint8_t k_seen, k_seen_valid;  /* FMP K bit last seen on an established frame */
    uint8_t tx[FIPS_MTU];
    uint8_t pt[FIPS_MTU];
    uint32_t heartbeat_ms, dead_ms;
} fips_t;

/* Unix seconds derived from the upstream's tree timestamps (monotonic); 0 until the upstream's TreeAnnounce was seen. */
uint64_t fips_unix_now(fips_t *f, uint64_t now_ms);

/* Read trace event number i (0 = oldest still stored). Returns 0 if out of range. */
int fips_trace_get(const fips_t *f, uint32_t abs_index, fips_trace_t *out);

/* ---- API ---- */

/* secret: our Nostr secret key. upstream_xonly: the upstream peer's 32-byte x-only pubkey. */
int fips_init(fips_t *f, const fips_io_t *io, const uint8_t secret[32], const uint8_t upstream_xonly[32]);

/* Begin (or restart) the link handshake: sends msg1. */
int fips_connect(fips_t *f, uint64_t now_ms);

/* Feed one received UDP datagram from the upstream peer. */
int fips_input(fips_t *f, const uint8_t *dgram, size_t len, uint64_t now_ms);

/* Call at least every ~250 ms: msg1 resends, heartbeats, liveness timeout, session setup resends.
 * Reconnects automatically after a timeout. */
void fips_tick(fips_t *f, uint64_t now_ms);

int fips_link_state(const fips_t *f);

/* Our node address (first 16 bytes of SHA-256 of the x-only pubkey) and fd00::/8 IPv6 address. */
const uint8_t *fips_node_addr(const fips_t *f);
void fips_ipv6_addr(const uint8_t node_addr[16], uint8_t out[16]);

/* Open an end-to-end session to dest (x-only pubkey). The destination is routed by the
 * upstream peer; if dest == upstream it is the direct neighbour. Returns slot index >= 0. */
int fips_session_open(fips_t *f, const uint8_t dest_xonly[32], uint64_t now_ms);
int fips_session_ready(const fips_t *f, const uint8_t dest_xonly[32]);

/* Send a port-multiplexed datagram over an established session. */
int fips_send_data(fips_t *f, const uint8_t dest_xonly[32], uint16_t src_port, uint16_t dst_port,
                   const uint8_t *payload, size_t len, uint64_t now_ms);

/* Send a raw packet (e.g. an IPv4 packet) as FSP EndpointData over an established session.
 * len <= FIPS_MAX_PACKET. */
#define FIPS_MAX_PACKET 1280
int fips_send_packet(fips_t *f, const uint8_t dest_xonly[32], const uint8_t *pkt, size_t len, uint64_t now_ms);

/* Orderly shutdown: sends Disconnect(Shutdown). */
void fips_disconnect(fips_t *f, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
