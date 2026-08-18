/**
 * @file attack_handshake.h
 * @brief Interface for the WPA/WPA2 4-way handshake capture attack.
 *
 * Passively (or actively, via attack_deauth) captures the handshake for a
 * target AP and serializes it into PCAP and HCCAPX buffers as frames arrive.
 * Retrieve results via the pcap_serializer / hccapx_serializer getters once
 * hccapx_serializer_get() returns non-NULL.
 */
#ifndef ATTACK_HANDSHAKE_H
#define ATTACK_HANDSHAKE_H

#include <stdbool.h>
#include "esp_wifi_types.h"

/**
 * @brief Starts passive handshake capture against the given AP.
 *
 * Does not itself trigger a deauth/reconnect - combine with attack_deauth to
 * force a fresh handshake from an already-connected client.
 * To stop, call attack_handshake_stop().
 */
void attack_handshake_start(const wifi_ap_record_t *ap_record);

/**
 * @brief Stops the handshake capture attack.
 */
void attack_handshake_stop();

/**
 * @brief Returns true once a complete handshake message pair has been captured.
 */
bool attack_handshake_is_complete();

#endif
