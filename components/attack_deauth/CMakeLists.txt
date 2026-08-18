idf_component_register(
    SRCS "attack_deauth.c" "wsl_bypasser.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi
    PRIV_REQUIRES esp_timer
)

# wsl_bypasser.c intentionally redefines ieee80211_raw_frame_sanity_check, which
# also exists in the closed-source libnet80211.a blob. -zmuldefs tells the linker
# to allow (and prefer our) duplicate symbol instead of erroring.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,-zmuldefs")
