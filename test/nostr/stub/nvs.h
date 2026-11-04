#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t; typedef int nvs_handle_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NO_FREE_PAGES 1
#define ESP_ERR_NVS_NEW_VERSION_FOUND 2
#define NVS_READWRITE 1
esp_err_t nvs_open(const char*,int,nvs_handle_t*); esp_err_t nvs_get_blob(nvs_handle_t,const char*,void*,size_t*);
esp_err_t nvs_set_blob(nvs_handle_t,const char*,const void*,size_t); esp_err_t nvs_commit(nvs_handle_t); void nvs_close(nvs_handle_t);
esp_err_t nvs_flash_init(void); esp_err_t nvs_flash_erase(void);
esp_err_t esp_netif_init(void); esp_err_t esp_event_loop_create_default(void); esp_err_t example_connect(void);
#define ESP_ERROR_CHECK(x) (void)(x)
void esp_fill_random(void*,size_t); long long esp_timer_get_time(void);
