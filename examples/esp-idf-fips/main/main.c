/* Example: ESP32 as a FIPS leaf node (sans-IO library + lwIP UDP socket).
 *
 *  1. creates (once) a Nostr/FIPS identity and keeps it in NVS; prints its npub
 *  2. connects over Wi-Fi (protocol_examples_common: set SSID in menuconfig)
 *  3. opens a FIPS link to the upstream node you configure in menuconfig
 *     ("FIPS leaf example"), optionally opens an end-to-end session to a destination
 *     node and sends a datagram every 10 s; incoming datagrams are logged.
 *
 * The upstream must be a `fips` daemon with a UDP transport reachable from the board
 * (bind_addr 0.0.0.0:2121, not 127.0.0.1) and, if it uses an ACL, must allow this npub.
 * NOT yet verified on real hardware; the same library code was verified against the Rust daemon on Linux.
 */
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "protocol_examples_common.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "fips.h"
#include "nvpn.h"

static const char *TAG = "fips";

static fips_t g_node; /* several KiB: keep it off the task stack */
static int g_sock = -1;

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

static void io_send(void *ud, const uint8_t *p, size_t n) {
    (void)ud;
    if (g_sock >= 0 && send(g_sock, p, n, 0) < 0) ESP_LOGW(TAG, "send failed: errno %d", errno);
}
static void io_random(void *ud, uint8_t *b, size_t n) { (void)ud; esp_fill_random(b, n); }
static void io_on_data(void *ud, const uint8_t src[16], uint16_t sp, uint16_t dp, const uint8_t *p, size_t n) {
    char hex[33];
    (void)ud;
    nvpn_hex_encode(src, 16, hex);
    ESP_LOGI(TAG, "DATA from %s port %u->%u (%u bytes): %.*s", hex, sp, dp, (unsigned)n, (int)n, (const char *)p);
}

static esp_err_t load_or_create_secret(uint8_t sk[32]) {
    nvs_handle_t h;
    size_t len = 32;
    esp_err_t e = nvs_open("fips", NVS_READWRITE, &h);
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

static int open_socket(void) {
    struct addrinfo hints = {0}, *res = NULL;
    char port[8];
    int s;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(port, sizeof port, "%d", CONFIG_FIPS_UPSTREAM_PORT);
    if (getaddrinfo(CONFIG_FIPS_UPSTREAM_HOST, port, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "cannot resolve %s", CONFIG_FIPS_UPSTREAM_HOST);
        return -1;
    }
    s = socket(res->ai_family, SOCK_DGRAM, 0);
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) != 0) { close(s); s = -1; }
    freeaddrinfo(res);
    return s;
}

static void fips_task(void *arg) {
    uint8_t sk[32], pk[32], up[32], dest[32];
    char npub[70];
    int have_dest = 0, last_state = -1, session_started = 0;
    uint64_t last_tx = 0;
    static uint8_t rx[FIPS_MTU + 64];
    fips_io_t io = {io_send, io_random, io_on_data, NULL};
    (void)arg;

    if (load_or_create_secret(sk) != ESP_OK) { ESP_LOGE(TAG, "NVS identity failed"); vTaskDelete(NULL); }
    { uint8_t seed[32]; esp_fill_random(seed, 32); nvpn_secp_randomize(seed); }
    nvpn_pubkey_from_secret(sk, pk);
    if (nvpn_pubkey_to_npub(pk, npub, sizeof npub) == NVPN_OK) ESP_LOGI(TAG, "my identity: %s", npub);

    if (nvpn_pubkey_parse(CONFIG_FIPS_UPSTREAM_PUBKEY, up) != NVPN_OK) {
        ESP_LOGE(TAG, "set FIPS_UPSTREAM_PUBKEY in menuconfig (npub1... or hex)");
        vTaskDelete(NULL);
    }
    if (CONFIG_FIPS_DEST_PUBKEY[0]) {
        if (nvpn_pubkey_parse(CONFIG_FIPS_DEST_PUBKEY, dest) != NVPN_OK) { ESP_LOGE(TAG, "bad FIPS_DEST_PUBKEY"); vTaskDelete(NULL); }
        have_dest = 1;
    }

    while ((g_sock = open_socket()) < 0) vTaskDelay(pdMS_TO_TICKS(3000));
    if (fips_init(&g_node, &io, sk, up) != FIPS_OK) { ESP_LOGE(TAG, "fips_init failed"); vTaskDelete(NULL); }
    fips_connect(&g_node, now_ms());

    for (;;) {
        fd_set fs;
        struct timeval tv = {0, 100000};
        int st;
        FD_ZERO(&fs);
        FD_SET(g_sock, &fs);
        if (select(g_sock + 1, &fs, NULL, NULL, &tv) > 0) {
            int n = recv(g_sock, rx, sizeof rx, 0);
            if (n > 0) {
                int rc = fips_input(&g_node, rx, (size_t)n, now_ms());
                if (rc != FIPS_OK) ESP_LOGD(TAG, "fips_input rc=%d (%d bytes)", rc, n);
            }
        }
        fips_tick(&g_node, now_ms());

        st = fips_link_state(&g_node);
        if (st != last_state) {
            ESP_LOGI(TAG, "link state -> %s", st == FIPS_LINK_UP ? "UP" : st == FIPS_LINK_HANDSHAKING ? "HANDSHAKING" : "DOWN");
            last_state = st;
            if (st != FIPS_LINK_UP) session_started = 0; /* sessions are dropped with the link */
        }
        if (have_dest && st == FIPS_LINK_UP) {
            if (!session_started && fips_session_open(&g_node, dest, now_ms()) >= 0) session_started = 1;
            if (session_started && fips_session_ready(&g_node, dest) && now_ms() - last_tx >= 10000) {
                const char *msg = CONFIG_FIPS_MESSAGE;
                int rc = fips_send_data(&g_node, dest, (uint16_t)CONFIG_FIPS_DEST_PORT, (uint16_t)CONFIG_FIPS_DEST_PORT,
                                        (const uint8_t *)msg, strlen(msg), now_ms());
                ESP_LOGI(TAG, "sent test datagram rc=%d", rc);
                last_tx = now_ms();
            }
        }
    }
}

void app_main(void) {
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        e = nvs_flash_init();
    }
    ESP_ERROR_CHECK(e);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect()); /* Wi-Fi credentials via menuconfig "Example Connection Configuration" */
    xTaskCreate(fips_task, "fips", 12288, NULL, 5, NULL);
}
