/* ESP32 as a member of a nostr-vpn virtual LAN.
 *
 *  1. Put the signed roster event JSON of your network into main/roster.json
 *     (the "event" object of the roster, as in nostr-vpn's signed-rosters.json), and add THIS device's
 *     npub (printed at boot) to the network in nostr-vpn first, so the roster contains it.
 *  2. menuconfig: Wi-Fi, upstream FIPS node (a reachable `fips`/nostr-vpn node, UDP) and trusted admin key.
 *  3. After boot the ESP32 has a normal lwIP interface "nv0" with its mesh IP 10.44.x.y/16:
 *     other members can ping it, open http://<mesh-ip>:8080/ or send UDP to <mesh-ip>:7777 (echo);
 *     the ESP32 itself can use ordinary sockets to any member's mesh IP.
 * Not yet verified on real hardware.
 */
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "protocol_examples_common.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvpn_netif.h"

static const char *TAG = "vlan";
extern const char roster_json_start[] asm("_binary_roster_json_start");
extern const char roster_json_end[] asm("_binary_roster_json_end");

static nvpn_roster_t g_roster;   /* ~4.5 KiB, must outlive the netif */

static esp_err_t load_or_create_secret(uint8_t sk[32]) {
    nvs_handle_t h; size_t len = 32;
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

/* UDP echo on 7777 */
static void udp_echo_task(void *arg) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    (void)arg;
    a.sin_family = AF_INET; a.sin_port = htons(7777); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0) { ESP_LOGE(TAG, "udp bind failed"); vTaskDelete(NULL); }
    for (;;) {
        char buf[512]; struct sockaddr_in from; socklen_t fl = sizeof from;
        int n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n > 0) { ESP_LOGI(TAG, "udp %d bytes from %s", n, inet_ntoa(from.sin_addr)); sendto(s, buf, n, 0, (struct sockaddr *)&from, fl); }
    }
}

/* Tiny HTTP server on 8080 */
static void http_task(void *arg) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    (void)arg;
    a.sin_family = AF_INET; a.sin_port = htons(8080); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 2) != 0) { ESP_LOGE(TAG, "http bind failed"); vTaskDelete(NULL); }
    for (;;) {
        int c = accept(s, NULL, NULL);
        static const char resp[] = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello from esp32 over nostr-vpn\r\n";
        if (c < 0) continue;
        char req[256]; recv(c, req, sizeof req, 0);
        send(c, resp, sizeof resp - 1, 0);
        close(c);
    }
}

void app_main(void) {
    nvpn_netif_cfg_t cfg;
    nvpn_roster_t *in = NULL;
    static nvpn_roster_t incoming;
    uint8_t pk[32], admin[32];
    char npub[70];
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { ESP_ERROR_CHECK(nvs_flash_erase()); e = nvs_flash_init(); }
    ESP_ERROR_CHECK(e);
    memset(&cfg, 0, sizeof cfg);
    ESP_ERROR_CHECK(load_or_create_secret(cfg.secret));
    { uint8_t seed[32]; esp_fill_random(seed, 32); nvpn_secp_randomize(seed); }
    nvpn_pubkey_from_secret(cfg.secret, pk);
    if (nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK) ESP_LOGI(TAG, "this device: %s  (add it to your nostr-vpn network)", npub);

    if (nvpn_pubkey_parse(CONFIG_NVPN_UPSTREAM_PUBKEY, cfg.upstream_pubkey) != NVPN_OK) { ESP_LOGE(TAG, "set NVPN_UPSTREAM_PUBKEY"); return; }
    if (nvpn_pubkey_parse(CONFIG_NVPN_TRUSTED_ADMIN, admin) != NVPN_OK) { ESP_LOGE(TAG, "set NVPN_TRUSTED_ADMIN"); return; }
    in = &incoming;
    e = nvpn_roster_verify(roster_json_start, (size_t)(roster_json_end - roster_json_start), in);
    if (e != NVPN_OK) { ESP_LOGE(TAG, "roster.json invalid (%d)", (int)e); return; }
    e = nvpn_roster_bootstrap(&g_roster, in, admin);
    if (e != NVPN_OK) { ESP_LOGE(TAG, "roster not signed by the trusted admin (%d)", (int)e); return; }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());

    cfg.upstream_host = CONFIG_NVPN_UPSTREAM_HOST;
    cfg.upstream_port = CONFIG_NVPN_UPSTREAM_PORT;
    cfg.roster = &g_roster;
    if (nvpn_netif_start(&cfg) != 0) { ESP_LOGE(TAG, "nvpn_netif_start failed"); return; }
    xTaskCreate(udp_echo_task, "udp_echo", 4096, NULL, 4, NULL);
    xTaskCreate(http_task, "http", 4096, NULL, 4, NULL);

    for (;;) {
        nvpn_tunnel_stats_t st;
        vTaskDelay(pdMS_TO_TICKS(10000));
        nvpn_netif_stats(&st);
        ESP_LOGI(TAG, "link %s, tx %u rx %u dropped %u rejected %u", nvpn_netif_link_up() ? "UP" : "down", (unsigned)st.tx_pkts, (unsigned)st.rx_pkts, (unsigned)st.tx_dropped, (unsigned)st.rx_rejected);
    }
}
