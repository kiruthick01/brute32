idf_component_register(
    SRCS "webserver.c" "dns_server.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi
    PRIV_REQUIRES wifi_controller esp_http_server esp_event esp_netif lwip
)
