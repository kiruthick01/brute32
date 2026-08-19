idf_component_register(
    SRCS "attack_evil_twin.c" "karma.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi
    PRIV_REQUIRES wifi_controller
)
