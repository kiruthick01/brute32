idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES wifi_controller attack_deauth attack_pmkid_handshake serializers storage console nvs_flash
)
