/**
 * @file attack_deauth.h
 * @brief Interface for the deauthentication (DoS) attack.
 *
 * Periodically injects forged 802.11 deauthentication frames for a target AP,
 * either at the broadcast address (kicks every associated client) or at one
 * specific client's MAC address ("targeted" deauth).
 */
#ifndef ATTACK_DEAUTH_H
#define ATTACK_DEAUTH_H

#include <stdint.h>
#include "esp_wifi_types.h"

/**
 * @brief Starts periodic deauthentication of the given AP.
 *
 * To stop, call attack_deauth_stop().
 *
 * @param ap_record target AP; its BSSID is forged as the frame's source
 * @param sta_mac specific client to target, or NULL to deauth every client
 * (destination = broadcast)
 * @param period_sec how often to (re-)send the deauth frame, in seconds
 */
void attack_deauth_start(const wifi_ap_record_t *ap_record, const uint8_t *sta_mac, unsigned period_sec);

/**
 * @brief Stops the deauthentication attack started by attack_deauth_start().
 */
void attack_deauth_stop();

#endif
