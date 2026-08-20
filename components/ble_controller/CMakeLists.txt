idf_component_register(
    SRCS "ble_controller.c"
    INCLUDE_DIRS "interface"
    PRIV_REQUIRES bt esp_timer
)
