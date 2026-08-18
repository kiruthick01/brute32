/**
 * @file hccapx_serializer.h
 * @brief Generates a HCCAPX (hashcat mode 2500/22000-ready) buffer from captured
 * WPA/WPA2 4-way handshake frames.
 */
#ifndef HCCAPX_SERIALIZER_H
#define HCCAPX_SERIALIZER_H

#include <stdint.h>

#include "frame_analyzer_types.h"

/**
 * @see Ref: https://hashcat.net/wiki/doku.php?id=hccapx
 */
typedef struct __attribute__((__packed__)) {
    uint32_t signature;
    uint32_t version;
    uint8_t message_pair;
    uint8_t essid_len;
    uint8_t essid[32];
    uint8_t keyver;
    uint8_t keymic[16];
    uint8_t mac_ap[6];
    uint8_t nonce_ap[32];
    uint8_t mac_sta[6];
    uint8_t nonce_sta[32];
    uint16_t eapol_len;
    uint8_t eapol[256];
} hccapx_t;

/**
 * @brief Creates a new HCCAPX buffer for given SSID, clearing any previous capture.
 *
 * @param ssid SSID of the AP the handshake frames will come from.
 * @param size length of SSID (not including a NUL terminator; max 32)
 */
void hccapx_serializer_init(const uint8_t *ssid, unsigned size);

/**
 * @brief Returns pointer to the HCCAPX buffer, or NULL if not enough handshake
 * messages have been captured yet to form a valid message pair.
 */
hccapx_t *hccapx_serializer_get();

/**
 * @brief Feeds a captured data frame containing an EAPoL-Key packet into the
 * handshake state machine, filling in the HCCAPX buffer as messages arrive.
 *
 * @param frame data frame with EAPoL-Key packet
 */
void hccapx_serializer_add_frame(data_frame_t *frame);

#endif
