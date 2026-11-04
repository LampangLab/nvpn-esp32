/* lwIP netif + worker task for the nvpn tunnel (ESP32 only). */
#if defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)

#include "nvpn_netif.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/ip4_addr.h"
#include "lwip/netdb.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"

static const char *TAG = "nvpn";

#define NV_MTU 1280

static nvpn_tunnel_t s_tun;            /* ~16 KiB, static on purpose */
static struct netif s_netif;
static SemaphoreHandle_t s_lock;
static QueueHandle_t s_txq;            /* tcpip thread -> worker; keeps lwIP socket calls out of the tcpip thread */
typedef struct { uint16_t len; uint8_t data[NV_MTU]; } tx_item_t;
#ifndef NVPN_TX_QUEUE_DEPTH
#define NVPN_TX_QUEUE_DEPTH 8
#endif
#define POLL_MS 10                      /* worst-case added tx latency */
static int s_sock = -1;
static int s_started;
static nvpn_netif_cfg_t s_cfg;

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

/* ---- tunnel I/O callbacks (called with s_lock held) ---- */
static void io_send(void *ud, const uint8_t *p, size_t n) { (void)ud; if (s_sock >= 0 && send(s_sock, p, n, 0) < 0) s_tun.stats.udp_tx_err++; }
static void io_random(void *ud, uint8_t *b, size_t n) { (void)ud; esp_fill_random(b, n); }
static void io_deliver(void *ud, const uint8_t *pkt, size_t len) {
    struct pbuf *p;
    (void)ud;
    p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
    if (!p) return;
    if (pbuf_take(p, pkt, (u16_t)len) != ERR_OK || s_netif.input(p, &s_netif) != ERR_OK) pbuf_free(p); /* tcpip_input posts without blocking */
}

/* ---- lwIP netif: IPv4 output (called from the tcpip thread) ---- */
static err_t nv_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    static tx_item_t it;               /* only ever used from the tcpip thread: keep it off its small stack */
    (void)netif; (void)ipaddr;
    if (p->tot_len > NV_MTU || p->tot_len == 0) return ERR_BUF;
    if (pbuf_copy_partial(p, it.data, p->tot_len, 0) != p->tot_len) return ERR_BUF;
    it.len = p->tot_len;
    return xQueueSend(s_txq, &it, 0) == pdTRUE ? ERR_OK : ERR_MEM;   /* full queue = dropped packet; TCP/ICMP recover */
}

static err_t nv_init(struct netif *netif) {
    netif->name[0] = 'n'; netif->name[1] = 'v';
    netif->output = nv_output;
    netif->mtu = NV_MTU;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

static void set_netif_ip(void) {
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, s_tun.self_ip[0], s_tun.self_ip[1], s_tun.self_ip[2], s_tun.self_ip[3]);
    IP4_ADDR(&mask, 255, 255, 0, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);
    netif_set_addr(&s_netif, &ip, &mask, &gw);
}

static int open_socket(void) {
    struct addrinfo hints, *res = NULL;
    char port[8];
    int s;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    snprintf(port, sizeof port, "%u", s_cfg.upstream_port);
    if (getaddrinfo(s_cfg.upstream_host, port, &hints, &res) != 0 || !res) return -1;
    s = socket(res->ai_family, SOCK_DGRAM, 0);
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) != 0) { close(s); s = -1; }
    freeaddrinfo(res);
    return s;
}

static void worker(void *arg) {
    static uint8_t rx[FIPS_MTU + 64];
    static tx_item_t it;
    int last_up = -1;
    (void)arg;
    for (;;) {
        fd_set fs; struct timeval tv = {0, POLL_MS * 1000}; int up;
        FD_ZERO(&fs); FD_SET(s_sock, &fs);
        if (select(s_sock + 1, &fs, NULL, NULL, &tv) > 0) {
            int n = recv(s_sock, rx, sizeof rx, 0);
            if (n > 0) { xSemaphoreTake(s_lock, portMAX_DELAY); nvpn_tunnel_input(&s_tun, rx, (size_t)n, now_ms()); xSemaphoreGive(s_lock); }
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        while (xQueueReceive(s_txq, &it, 0) == pdTRUE) nvpn_tunnel_output(&s_tun, it.data, it.len, now_ms());
        nvpn_tunnel_tick(&s_tun, now_ms());
        up = nvpn_tunnel_up(&s_tun);
        xSemaphoreGive(s_lock);
        if (up != last_up) { ESP_LOGI(TAG, "FIPS link %s", up ? "UP" : "DOWN"); last_up = up; }
    }
}

int nvpn_netif_start(const nvpn_netif_cfg_t *cfg) {
    nvpn_tunnel_io_t io = {io_send, io_random, io_deliver, NULL};
    ip4_addr_t z;
    int rc;
    if (!cfg || !cfg->upstream_host || !cfg->roster || s_started) return -1;
    s_cfg = *cfg;
    s_lock = xSemaphoreCreateMutex();
    s_txq = xQueueCreate(NVPN_TX_QUEUE_DEPTH, sizeof(tx_item_t));
    if (!s_lock || !s_txq) return -2;
    rc = nvpn_tunnel_init(&s_tun, &io, cfg->secret, cfg->upstream_pubkey, cfg->roster);
    if (rc != NVPN_OK) { ESP_LOGE(TAG, "tunnel init failed (%d): are we in the roster?", rc); return -3; }
    while ((s_sock = open_socket()) < 0) { ESP_LOGW(TAG, "cannot resolve/connect %s, retrying", cfg->upstream_host); vTaskDelay(pdMS_TO_TICKS(3000)); }

    ip4_addr_set_zero(&z);
    LOCK_TCPIP_CORE();
    if (!netif_add(&s_netif, &z, &z, &z, NULL, nv_init, tcpip_input)) { UNLOCK_TCPIP_CORE(); return -4; }
    set_netif_ip();
    netif_set_up(&s_netif);
    UNLOCK_TCPIP_CORE();
    ESP_LOGI(TAG, "mesh IP %u.%u.%u.%u/16", s_tun.self_ip[0], s_tun.self_ip[1], s_tun.self_ip[2], s_tun.self_ip[3]);

    nvpn_tunnel_start(&s_tun, now_ms());
    s_started = 1;
    if (xTaskCreate(worker, "nvpn", cfg->task_stack > 0 ? cfg->task_stack : 8192, NULL, cfg->task_priority > 0 ? cfg->task_priority : 5, NULL) != pdPASS) return -5;
    return 0;
}

int nvpn_netif_link_up(void) {
    int up;
    if (!s_started) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY); up = nvpn_tunnel_up(&s_tun); xSemaphoreGive(s_lock);
    return up;
}
void nvpn_netif_ip(uint8_t ip[4]) { memcpy(ip, s_tun.self_ip, 4); }
void nvpn_netif_stats(nvpn_tunnel_stats_t *out) { xSemaphoreTake(s_lock, portMAX_DELAY); *out = s_tun.stats; xSemaphoreGive(s_lock); }
int nvpn_netif_trace(uint32_t idx, fips_trace_t *out, uint32_t *total, uint8_t *role) {
    int rc;
    if (!s_started) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rc = fips_trace_get(&s_tun.fips, idx, out);
    if (total) *total = s_tun.fips.trace_n;
    if (role) *role = s_tun.fips.role;
    xSemaphoreGive(s_lock);
    return rc;
}
int nvpn_netif_roster_changed(void) {
    int rc;
    if (!s_started) return -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    rc = nvpn_tunnel_roster_changed(&s_tun);
    xSemaphoreGive(s_lock);
    if (rc == NVPN_OK) { LOCK_TCPIP_CORE(); set_netif_ip(); UNLOCK_TCPIP_CORE(); }
    return rc;
}

#endif /* ESP_PLATFORM */
