idf_component_register(
    SRCS "wifi_controller.c" "sniffer.c" "ap_scanner.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi esp_event
    PRIV_REQUIRES esp_netif
)
