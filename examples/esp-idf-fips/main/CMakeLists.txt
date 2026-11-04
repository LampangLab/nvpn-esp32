idf_component_register(SRCS "main.c" INCLUDE_DIRS "."
                       REQUIRES nvpn-esp32 esp_netif esp_timer esp_event protocol_examples_common nvs_flash lwip)
