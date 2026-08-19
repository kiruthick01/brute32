/**
 * @file attack_evil_twin.h
 * @brief Interface for the rogue AP / evil twin attack.
 *
 * Clones a target AP's BSSID, SSID and channel with open authentication so
 * clients associate freely, then runs a karma-style probe responder
 * alongside it. Pair with the `webserver` component for the captive-portal
 * credential-harvesting page.
 *
 * @note Karma limitation: esp_wifi's AP mode only completes real
 * associations for the one SSID it's actively configured with (the cloned
 * target). The karma responder answers probe requests for *any* SSID a
 * nearby device is looking for — which makes the rogue AP visually appear
 * as that network and can trigger a device's auto-join UI — but an actual
 * completed connection still requires the client to associate with our
 * real, single configured SSID. This is a real hardware/driver constraint,
 * not a missing feature.
 */
#ifndef ATTACK_EVIL_TWIN_H
#define ATTACK_EVIL_TWIN_H

#include <stdint.h>
#include "esp_wifi_types.h"

/**
 * @brief Starts the evil twin attack against the given AP.
 *
 * Clones BSSID/SSID/channel with open auth, brings up the rogue AP, and
 * starts the karma probe responder. To stop, call attack_evil_twin_stop().
 */
void attack_evil_twin_start(const wifi_ap_record_t *ap_record);

/**
 * @brief Stops the evil twin attack: restores the original AP MAC and
 * stops the karma responder. Does not stop the webserver.
 */
void attack_evil_twin_stop();

/**
 * @brief Returns the AP record currently being cloned, or NULL if the
 * attack isn't running. Used by `webserver` to verify submitted passwords
 * against the real network and to brand the captive portal page.
 */
const wifi_ap_record_t *attack_evil_twin_get_target();

/**
 * @brief Snapshot of one probe request observed by the karma responder.
 */
typedef struct {
    uint8_t sta_mac[6];
    uint8_t ssid[33];
    uint8_t ssid_len;
} karma_probe_t;

/**
 * @brief Returns up to max_count recently observed probe requests into out,
 * newest first.
 *
 * @return number of entries written to out
 */
unsigned attack_evil_twin_get_probe_log(karma_probe_t *out, unsigned max_count);

#endif
