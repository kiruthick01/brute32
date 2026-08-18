/**
 * @file wifi_controller.c
 * @brief Implements common Wi-Fi controller operations.
 *
 * Ported from risinek/esp32-wifi-penetration-tool (IDF 4.x) to ESP-IDF 5.x.
 * The esp_wifi/esp_netif APIs used here (esp_netif_create_default_wifi_ap/sta,
 * WIFI_INIT_CONFIG_DEFAULT, esp_wifi_set_mac, wifi_promiscuous_filter_t, ...)
 * are unchanged across this range, so the logic ports without modification;
 * only the wrapping (explicit init entrypoint, logging) was cleaned up.
 */
#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"

static const char *TAG = "wifi_controller";

static bool wifi_init_done = false;
static uint8_t original_mac_ap[6];

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGV(TAG, "wifi event %" PRId32, event_id);
}

static void wifi_init_apsta() {
    if (wifi_init_done) {
        return;
    }

    ESP_ERROR_CHECK(esp_netif_init());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init_done = true;
    ESP_LOGI(TAG, "Wi-Fi initialised in APSTA mode");
}

void wifictl_init() {
    wifi_init_apsta();
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    wifi_init_apsta();

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop() {
    ESP_LOGD(TAG, "Stopping AP...");
    wifi_config_t wifi_config = {
        .ap = {
            .max_connection = 0
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_LOGD(TAG, "AP stopped");
}

void wifictl_mgmt_ap_start() {
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = CONFIG_MGMT_AP_AUTH_ON ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN,
            .channel = CONFIG_MGMT_AP_CHANNEL,
        },
    };
    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]) {
    ESP_LOGD(TAG, "Connecting STA to AP...");
    wifi_init_apsta();

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false
        },
    };
    memcpy(sta_wifi_config.sta.ssid, ap_record->ssid, sizeof(sta_wifi_config.sta.ssid));

    if (password != NULL) {
        if (strlen(password) >= sizeof(sta_wifi_config.sta.password)) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is %d", (int) sizeof(sta_wifi_config.sta.password) - 1);
            return;
        }
        strlcpy((char *) sta_wifi_config.sta.password, password, sizeof(sta_wifi_config.sta.password));
    }

    ESP_LOGD(TAG, ".ssid=%s", sta_wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
}

void wifictl_sta_disconnect() {
    ESP_ERROR_CHECK(esp_wifi_disconnect());
}

void wifictl_set_ap_mac(const uint8_t *mac_ap) {
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap) {
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_restore_ap_mac() {
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta) {
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, mac_sta));
}

void wifictl_set_channel(uint8_t channel) {
    if ((channel == 0) || (channel > 13)) {
        ESP_LOGE(TAG, "Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    ESP_ERROR_CHECK(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE));
}
