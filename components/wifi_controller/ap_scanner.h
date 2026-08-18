/**
 * @file ap_scanner.h
 * @brief Interface for AP scanning functionality.
 */
#ifndef AP_SCANNER_H
#define AP_SCANNER_H

#include "esp_wifi_types.h"

/**
 * @brief Snapshot of nearby AP records from the last scan.
 */
typedef struct {
    uint16_t count;
    wifi_ap_record_t records[CONFIG_SCAN_MAX_AP];
} wifictl_ap_records_t;

/**
 * @brief Switches ESP into scanning mode and stores result.
 */
void wifictl_scan_nearby_aps();

/**
 * @brief Returns current list of scanned APs.
 */
const wifictl_ap_records_t *wifictl_get_ap_records();

/**
 * @brief Returns AP record at given index, or NULL if out of bounds.
 */
const wifi_ap_record_t *wifictl_get_ap_record(unsigned index);

#endif
