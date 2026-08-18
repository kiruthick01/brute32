/**
 * @file attack_pmkid.h
 * @brief Interface for the PMKID capture attack.
 *
 * @see PMKID attack reference: https://hashcat.net/forum/thread-7717.html
 */
#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include "esp_wifi_types.h"

/**
 * @brief Result of a finished PMKID capture.
 */
typedef struct {
    uint8_t sta_mac[6];
    uint8_t ap_mac[6];
    uint8_t ssid[33];
    uint8_t ssid_len;
    uint8_t pmkid[16];
} attack_pmkid_result_t;

/**
 * @brief Starts the PMKID attack against the given AP.
 *
 * Connects the station interface to the AP with a dummy password to solicit
 * the (M1) EAPoL frame carrying the PMKID, then sniffs for it.
 * To stop early, call attack_pmkid_stop().
 */
void attack_pmkid_start(const wifi_ap_record_t *ap_record);

/**
 * @brief Stops the PMKID attack and releases its resources.
 */
void attack_pmkid_stop();

/**
 * @brief Returns the last captured PMKID result, or NULL if none is available yet.
 */
const attack_pmkid_result_t *attack_pmkid_get_result();

#endif
