idf_component_register(
    SRCS "pcap_serializer.c" "hccapx_serializer.c"
    INCLUDE_DIRS "interface"
    REQUIRES frame_analyzer
    PRIV_REQUIRES lwip
)
