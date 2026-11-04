#include <stdio.h>
#include <errno.h>
#define ESP_LOGI(t,...) printf(__VA_ARGS__)
#define ESP_LOGW ESP_LOGI
#define ESP_LOGE ESP_LOGI
#define ESP_LOGD ESP_LOGI
