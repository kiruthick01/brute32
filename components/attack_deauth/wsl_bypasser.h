/**
 * @file wsl_bypasser.h
 * @brief Bypasses the Wi-Fi Stack Libraries' blocking mechanism that otherwise
 * prevents transmitting arbitrary raw 802.11 management frames (e.g. deauth).
 *
 * Internal to attack_deauth; not part of the component's public interface.
 */
#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include "esp_wifi_types.h"

/**
 * @brief Sends frame_buffer via esp_wifi_80211_tx, bypassing the sanity check
 * that blocks raw injection of certain frame types.
 */
void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);

/**
 * @brief Sends a deauthentication frame forged as coming from ap_record's BSSID.
 *
 * @param ap_record target AP whose BSSID is forged as the frame's source
 * @param sta_mac destination MAC (the client being deauthed), or NULL to
 * target the broadcast address ff:ff:ff:ff:ff:ff (deauth all clients of the AP)
 */
void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record, const uint8_t *sta_mac);

#endif
