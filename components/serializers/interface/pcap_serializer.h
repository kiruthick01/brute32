/**
 * @file pcap_serializer.h
 * @brief Generates a PCAP-formatted binary buffer from raw 802.11 frame bytes.
 */
#ifndef PCAP_SERIALIZER_H
#define PCAP_SERIALIZER_H

#include <stdint.h>

/**
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

/**
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat
 */
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header_t;

/**
 * @brief Prepares a new empty buffer for PCAP formatted binary data.
 *
 * Must be called before pcap_serializer_append_frame(). Frees any buffer
 * left over from a previous capture.
 *
 * @return pointer to newly allocated PCAP buffer, NULL on allocation failure.
 */
uint8_t *pcap_serializer_init();

/**
 * @brief Appends a new frame to the current PCAP buffer.
 *
 * @param buffer frame buffer to append
 * @param size size of frame buffer
 * @param ts_usec timestamp of captured frame in microseconds
 */
void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec);

/**
 * @brief Frees the PCAP buffer and resets state.
 */
void pcap_serializer_deinit();

/**
 * @brief Returns size of the PCAP buffer in bytes.
 */
unsigned pcap_serializer_get_size();

/**
 * @brief Returns pointer to the PCAP buffer.
 */
uint8_t *pcap_serializer_get_buffer();

#endif
