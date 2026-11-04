/* Example: ESP32 as a MagicDNS responder for a nostr-vpn network.
 *
 *  1. creates (once) and stores a Nostr identity in NVS
 *  2. verifies a signed roster you paste into ROSTER_JSON (BIP-340 + event id)
 *  3. answers DNS queries for roster aliases on UDP/53
 *
 * Get ROSTER_JSON from an admin device's signed-rosters.json (the "event" object
 * of the roster for your network). Requires correct wall-clock time only if you
 * enable the freshness check below.
 */
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "protocol_examples_common.h"
#include "lwip/sockets.h"
#include "nvpn.h"

static const char *TAG = "nvpn";

/* Paste the roster event JSON here (raw string). */
static const char ROSTER_JSON[] = "{}";
/* Admin pubkey you trust for the first roster (hex or npub). */
static const char TRUSTED_ADMIN[] = "";
static const char MAGICDNS_SUFFIX[] = "nvpn";

static nvpn_roster_t g_roster, g_incoming; /* ~4.5 KiB each: keep off the task stack */

static esp_err_t load_or_create_secret(uint8_t sk[32]) {
    nvs_handle_t h;
    size_t len = 32;
    esp_err_t e = nvs_open("nvpn", NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_get_blob(h, "sk", sk, &len);
    if (e != ESP_OK || len != 32) {
        uint8_t pk[32];
        do { esp_fill_random(sk, 32); } while (nvpn_pubkey_from_secret(sk, pk) != NVPN_OK);
        e = nvs_set_blob(h, "sk", sk, 32);
        if (e == ESP_OK) e = nvs_commit(h);
    }
    nvs_close(h);
    return e;
}

void app_main(void) {
    uint8_t sk[32], pk[32], ip[4], admin[32], seed[32];
    char npub[80];

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect()); /* Wi-Fi/Ethernet via menuconfig */

    esp_fill_random(seed, 32);
    nvpn_secp_randomize(seed);

    ESP_ERROR_CHECK(load_or_create_secret(sk));
    if (nvpn_pubkey_from_secret(sk, pk) != NVPN_OK) { ESP_LOGE(TAG, "bad key"); return; }
    nvpn_pubkey_to_npub(pk, npub, sizeof npub);
    ESP_LOGI(TAG, "device identity: %s", npub);

    {
        int rc = nvpn_roster_verify(ROSTER_JSON, sizeof ROSTER_JSON - 1, &g_incoming);
        if (rc != NVPN_OK) { ESP_LOGE(TAG, "roster rejected: %d (paste a real roster into ROSTER_JSON)", rc); return; }
        if (nvpn_pubkey_parse(TRUSTED_ADMIN, admin) != NVPN_OK ||
            nvpn_roster_bootstrap(&g_roster, &g_incoming, admin) != NVPN_OK) {
            ESP_LOGE(TAG, "roster not signed by the trusted admin"); return;
        }
    }
    if (!nvpn_roster_is_member(&g_roster, pk)) ESP_LOGW(TAG, "this device is not in the roster (ask the admin to approve %s)", npub);
    if (nvpn_derive_tunnel_ip(g_roster.network_id, pk, ip) == NVPN_OK)
        ESP_LOGI(TAG, "mesh address: %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

    {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(INADDR_ANY)};
        if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) < 0) { ESP_LOGE(TAG, "bind :53 failed"); return; }
        ESP_LOGI(TAG, "MagicDNS (.%s) listening on :53", MAGICDNS_SUFFIX);
        for (;;) {
            uint8_t q[512], r[512];
            struct sockaddr_in from; socklen_t fl = sizeof from;
            int n = recvfrom(s, q, sizeof q, 0, (struct sockaddr *)&from, &fl);
            if (n <= 0) continue;
            n = nvpn_dns_respond(&g_roster, MAGICDNS_SUFFIX, 1, q, (size_t)n, r, sizeof r);
            if (n > 0) sendto(s, r, (size_t)n, 0, (struct sockaddr *)&from, fl);
        }
    }
}
