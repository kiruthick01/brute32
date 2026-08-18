/**
 * @file hccapx_serializer.c
 * @brief Implements the HCCAPX serializer as a small state machine tracking
 * the 4 messages of a WPA/WPA2 handshake.
 *
 * WPA handshake pseudo-diagram:
 * @code{.unparsed}
 * AP           STA
 * M1 ---------> |
 * | <--------- M2
 * M3 ---------> |
 * | <--------- M4
 * @endcode
 */
#include "hccapx_serializer.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "arpa/inet.h"
#include "esp_log.h"

#include "frame_analyzer.h"
#include "frame_analyzer_types.h"
#include "frame_analyzer_parser.h"

/**
 * @see Ref: https://hashcat.net/wiki/doku.php?id=hccapx
 */
#define HCCAPX_SIGNATURE 0x58504348
#define HCCAPX_VERSION 4
#define HCCAPX_KEYVER_WPA 1
#define HCCAPX_KEYVER_WPA2 2
#define HCCAPX_MAX_EAPOL_SIZE 256

static const char *TAG = "hccapx_serializer";

static hccapx_t hccapx = {
    .signature = HCCAPX_SIGNATURE,
    .version = HCCAPX_VERSION,
    .message_pair = 255,
    .keyver = HCCAPX_KEYVER_WPA2
};

/**
 * @brief Last processed message number, per direction.
 */
static unsigned message_ap = 0;
static unsigned message_sta = 0;

/**
 * @brief Message number from which the currently saved EAPoL packet came.
 */
static unsigned eapol_source = 0;

static bool is_array_zero(const uint8_t *array, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        if (array[i] != 0) {
            return false;
        }
    }
    return true;
}

void hccapx_serializer_init(const uint8_t *ssid, unsigned size) {
    if (size > sizeof(hccapx.essid)) {
        size = sizeof(hccapx.essid);
    }
    hccapx.essid_len = size;
    memcpy(hccapx.essid, ssid, size);
    hccapx.message_pair = 255;
    message_ap = 0;
    message_sta = 0;
    eapol_source = 0;
}

hccapx_t *hccapx_serializer_get() {
    if (hccapx.message_pair == 255) {
        return NULL;
    }
    return &hccapx;
}

/**
 * @brief Saves an EAPoL-Key frame into the HCCAPX buffer and clears the MIC
 * field per hashcat's expected preprocessing (802.11i-2004 [8.5.2/h]).
 *
 * @return 1 on error, 0 on success
 */
static unsigned save_eapol(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    unsigned eapol_len = sizeof(eapol_packet_header_t) + ntohs(eapol_packet->header.packet_body_length);
    if (eapol_len > HCCAPX_MAX_EAPOL_SIZE) {
        ESP_LOGW(TAG, "EAPoL is too long (%u/%u)", eapol_len, HCCAPX_MAX_EAPOL_SIZE);
        return 1;
    }
    hccapx.eapol_len = eapol_len;
    memcpy(hccapx.eapol, eapol_packet, hccapx.eapol_len);
    memcpy(hccapx.keymic, eapol_key_packet->key_mic, 16);
    // Key MIC offset: 4 bytes EAPoL header + 77 bytes into EAPoL-Key.
    // Not documented in the HCCAPX reference; derived from 802.11i-2004 [8.5.2/h]
    // and cap2hccapx's behaviour so hashcat can compute the MIC without preprocessing.
    memset(&hccapx.eapol[81], 0x0, 16);
    return 0;
}

/** @brief M1: AP -> STA, always contains ANonce. */
static void ap_message_m1(eapol_key_packet_t *eapol_key_packet) {
    ESP_LOGD(TAG, "From AP M1");
    message_ap = 1;
    memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce, 32);
}

/** @brief M3: AP -> STA. */
static void ap_message_m3(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    ESP_LOGD(TAG, "From AP M3");
    if (message_ap == 0) {
        // No AP message processed yet; ANonce has to be copied from here.
        memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce, 32);
    }
    message_ap = 3;
    if (eapol_source == 2) {
        // EAPoL packet already saved from message #2, no need to resave.
        hccapx.message_pair = 2;
        return;
    }
    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }
    eapol_source = 3;
    if (message_sta == 2) {
        hccapx.message_pair = 3;
    }
}

/** @brief Handles AP-origin messages (M1, M3). */
static void ap_message(data_frame_t *frame, eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    if ((!is_array_zero(hccapx.mac_sta, 6)) && (memcmp(frame->mac_header.addr1, hccapx.mac_sta, 6) != 0)) {
        ESP_LOGE(TAG, "Different STA");
        return;
    }
    if (message_ap == 0) {
        memcpy(hccapx.mac_ap, frame->mac_header.addr2, 6);
    }
    // Key MIC is always empty in M1, always present in M3 (802.11i-2004 [8.5.3])
    if (is_array_zero(eapol_key_packet->key_mic, 16)) {
        ap_message_m1(eapol_key_packet);
    } else {
        ap_message_m3(eapol_packet, eapol_key_packet);
    }
}

/** @brief M2: STA -> AP. First message with a MIC present; saves SNonce. */
static void sta_message_m2(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    ESP_LOGD(TAG, "From STA M2");
    message_sta = 2;
    memcpy(hccapx.nonce_sta, eapol_key_packet->key_nonce, 32);
    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }
    eapol_source = 2;
    if (message_ap == 1) {
        hccapx.message_pair = 0;
    }
}

/** @brief M4: STA -> AP. */
static void sta_message_m4(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    ESP_LOGD(TAG, "From STA M4");
    if ((message_sta == 2) && (eapol_source != 0)) {
        ESP_LOGD(TAG, "Already have M2, not worth saving M4");
        return;
    }
    if (message_ap == 0) {
        ESP_LOGE(TAG, "Not enough handshake messages received.");
        return;
    }
    if (eapol_source == 3) {
        hccapx.message_pair = 4;
        return;
    }
    if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
        return;
    }
    eapol_source = 4;
    if (message_ap == 1) {
        hccapx.message_pair = 1;
    }
    if (message_ap == 3) {
        hccapx.message_pair = 5;
    }
}

/** @brief Handles STA-origin messages (M2, M4). */
static void sta_message(data_frame_t *frame, eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
    if (is_array_zero(hccapx.mac_sta, 6)) {
        memcpy(hccapx.mac_sta, frame->mac_header.addr2, 6);
    } else if (memcmp(frame->mac_header.addr2, hccapx.mac_sta, 6) != 0) {
        ESP_LOGE(TAG, "Different STA");
        return;
    }
    // SNonce is present in M2, empty in M4 (802.11i-2004 [8.5.3])
    if (!is_array_zero(eapol_key_packet->key_nonce, 16)) {
        sta_message_m2(eapol_packet, eapol_key_packet);
    } else {
        sta_message_m4(eapol_packet, eapol_key_packet);
    }
}

void hccapx_serializer_add_frame(data_frame_t *frame) {
    eapol_packet_t *eapol_packet = parse_eapol_packet(frame);
    eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(eapol_packet);
    if (eapol_key_packet == NULL) {
        return;
    }
    // Determine frame direction by comparing BSSID (addr3) with source address (addr2)
    if (memcmp(frame->mac_header.addr2, frame->mac_header.addr3, 6) == 0) {
        ap_message(frame, eapol_packet, eapol_key_packet);
    } else if (memcmp(frame->mac_header.addr1, frame->mac_header.addr3, 6) == 0) {
        sta_message(frame, eapol_packet, eapol_key_packet);
    } else {
        ESP_LOGE(TAG, "Unknown frame format. BSSID is not source nor destination.");
    }
}
