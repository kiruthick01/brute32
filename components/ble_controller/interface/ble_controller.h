/**
 * @file ble_controller.h
 * @brief Interface for BLE operations: NimBLE bring-up, advertisement scanning
 * with device fingerprinting, and advertising-layer spam/jamming demos.
 *
 * Scanning is a passive GAP central role (no connections attempted). Spam is
 * a peripheral role that cycles forged manufacturer/service advertising data
 * to trigger OS-level pairing popups on nearby phones — disruptive by
 * design, isolated-test-environment only. See PROJECT_PLAN.md Phase 3.
 */
#ifndef BLE_CONTROLLER_H
#define BLE_CONTROLLER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Initializes the NimBLE host and starts its FreeRTOS task. Safe to
 * call once; must be called before any scan/spam function.
 */
void ble_controller_init(void);

// --- scanning ---

typedef struct {
    uint8_t addr[6];
    uint8_t addr_type;
    int8_t rssi;
    char name[32];
    uint8_t name_len;
    uint16_t company_id;      // manufacturer data company ID, 0xFFFF if none seen
    uint8_t mfg_data[16];
    uint8_t mfg_data_len;
    bool connectable;
} ble_device_t;

/**
 * @brief Starts a passive GAP scan, deduping discovered devices by address
 * into an in-memory table (see ble_controller_get_devices).
 *
 * @param duration_sec how long to scan, or 0 to scan until ble_controller_scan_stop()
 */
void ble_controller_scan_start(unsigned duration_sec);

/**
 * @brief Stops a running scan started by ble_controller_scan_start().
 */
void ble_controller_scan_stop(void);

/**
 * @brief True while a scan is in progress.
 */
bool ble_controller_scan_is_running(void);

/**
 * @brief Copies discovered devices (newest scan session) into out.
 * @return number of devices copied
 */
unsigned ble_controller_get_devices(ble_device_t *out, unsigned max);

/**
 * @brief Clears the discovered-device table.
 */
void ble_controller_clear_devices(void);

// --- spam ---

typedef enum {
    BLE_SPAM_APPLE,   // Apple Continuity "Nearby Action" popups (AirPods/Setup New Device/etc.)
    BLE_SPAM_ANDROID, // Google Fast Pair service-data popups
    BLE_SPAM_ALL,     // alternates both payload families
} ble_spam_mode_t;

/**
 * @brief Starts cycling forged advertising payloads, restarting advertising
 * with a new random payload + randomized advertising address every
 * interval_ms so each broadcast reads as a distinct nearby device.
 */
void ble_controller_spam_start(ble_spam_mode_t mode, unsigned interval_ms);

/**
 * @brief Stops spam started by ble_controller_spam_start().
 */
void ble_controller_spam_stop(void);

/**
 * @brief True while spam is running.
 */
bool ble_controller_spam_is_running(void);

#endif
