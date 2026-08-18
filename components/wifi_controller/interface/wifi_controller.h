/**
 * @file wifi_controller.h
 * @brief Interface for common Wi-Fi operations: AP/STA control, MAC spoofing, channel control.
 *
 * Ported from risinek/esp32-wifi-penetration-tool to ESP-IDF 5.x for esp32s3.
 */
#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

#include <stdint.h>
#include <unistd.h>

#include "../ap_scanner.h"
#include "../sniffer.h"

#include "esp_wifi_types.h"

/**
 * @brief Initializes Wi-Fi in APSTA mode. Safe to call multiple times.
 */
void wifictl_init();

/**
 * @brief Starts AP with given config
 */
void wifictl_ap_start(wifi_config_t *wifi_config);

/**
 * @brief Stops running AP
 */
void wifictl_ap_stop();

/**
 * @brief Starts default management AP (Kconfig-configured SSID/password)
 */
void wifictl_mgmt_ap_start();

/**
 * @brief Connects station interface to the given AP
 */
void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]);

/**
 * @brief Disconnects station interface from currently connected AP
 */
void wifictl_sta_disconnect();

/**
 * @brief Sets AP interface MAC address
 */
void wifictl_set_ap_mac(const uint8_t *mac_ap);

/**
 * @brief Saves current AP interface MAC to given parameter (6 bytes, pre-allocated)
 */
void wifictl_get_ap_mac(uint8_t *mac_ap);

/**
 * @brief Restores original AP interface MAC that was set during Wi-Fi initialisation.
 */
void wifictl_restore_ap_mac();

/**
 * @brief Saves current STA interface MAC to given parameter (6 bytes, pre-allocated)
 */
void wifictl_get_sta_mac(uint8_t *mac_sta);

/**
 * @brief Sets new channel for Wi-Fi interface (1-13)
 */
void wifictl_set_channel(uint8_t channel);

#endif
