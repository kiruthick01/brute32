idf_component_register(
    SRCS "attack_pmkid.c" "attack_handshake.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi
    PRIV_REQUIRES wifi_controller frame_analyzer serializers esp_event
)
